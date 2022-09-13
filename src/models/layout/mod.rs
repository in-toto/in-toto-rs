//! in-toto layout: used by the project owner to generate a desired supply chain layout file.

use std::collections::BTreeMap;

use chrono::prelude::*;
use chrono::TimeZone;
use chrono::{DateTime, Utc};
use log::warn;
use serde_derive::{Deserialize, Serialize};

use crate::crypto::{KeyId, PublicKey};
use crate::{Error, Result};

use self::{inspection::Inspection, step::Step};

pub mod inspection;
pub mod metadata;
pub mod rule;
pub mod step;
pub mod supply_chain_item;

pub use metadata::{LayoutMetadata, LayoutMetadataBuilder};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Layout {
    #[serde(rename = "_type")]
    typ: String,
    expires: String,
    readme: String,
    keys: BTreeMap<KeyId, PublicKey>,
    steps: Vec<Step>,
    inspect: Vec<Inspection>,
}

impl Layout {
    pub fn from(meta: &LayoutMetadata) -> Result<Self> {
        Ok(Layout {
            typ: String::from("layout"),
            expires: format_datetime(meta.expires()),
            readme: meta.readme().to_string(),
            keys: meta
                .keys()
                .iter()
                .map(|(id, key)| (id.clone(), key.clone()))
                .collect(),
            steps: (*meta.steps()).clone(),
            inspect: (*meta.inspect()).clone(),
        })
    }

    pub fn try_into(self) -> Result<LayoutMetadata> {
        // Ignore all keys with incorrect key IDs.
        // If a malformed key is used, there will be a warning
        let keys_with_correct_key_id = self
            .keys
            .into_iter()
            .filter(|(key_id, pkey)| match key_id == pkey.key_id() {
                true => true,
                false => {
                    warn!("Malformed key of ID {:?}", key_id);
                    false
                }
            })
            .collect();

        Ok(LayoutMetadata::new(
            parse_datetime(&self.expires)?,
            self.readme,
            keys_with_correct_key_id,
            self.steps,
            self.inspect,
        ))
    }
}

fn parse_datetime(ts: &str) -> Result<DateTime<Utc>> {
    Utc.datetime_from_str(ts, "%FT%TZ")
        .map_err(|e| Error::Encoding(format!("Can't parse DateTime: {:?}", e)))
}

fn format_datetime(ts: &DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod test {
    use chrono::{DateTime, NaiveDateTime, Utc};
    use serde_json::json;

    use crate::{crypto::PublicKey, models::layout::format_datetime};

    use super::{
        inspection::Inspection, parse_datetime, rule::ArtifactRuleBuilder, step::Step, Layout,
        LayoutMetadataBuilder,
    };

    const ALICE_PUB_KEY: &'static [u8] = include_bytes!("../../../tests/ed25519/ed25519-1.pub");
    const BOB_PUB_KEY: &'static [u8] = include_bytes!("../../../tests/rsa/rsa-4096.spki.der");

    #[test]
    fn parse_datetime_test() {
        let time_str = "1970-01-01T00:00:00Z".to_string();
        let parsed_dt = parse_datetime(&time_str[..]).unwrap();
        let dt = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc);
        assert_eq!(parsed_dt, dt);
    }

    #[test]
    fn format_datetime_test() {
        let dt = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc);
        let generated_dt_str = format_datetime(&dt);
        let dt_str = "1970-01-01T00:00:00Z".to_string();
        assert_eq!(dt_str, generated_dt_str);
    }

    fn get_example_layout_metadata() -> Layout {
        let alice_key = PublicKey::from_ed25519(ALICE_PUB_KEY).unwrap();
        let bob_key =
            PublicKey::from_spki(BOB_PUB_KEY, crate::crypto::SignatureScheme::RsaSsaPssSha256)
                .unwrap();
        let metadata = LayoutMetadataBuilder::new()
            .expires(DateTime::<Utc>::from_utc(
                NaiveDateTime::from_timestamp(0, 0),
                Utc,
            ))
            .add_key(alice_key.clone())
            .add_key(bob_key.clone())
            .add_step(
                Step::new("write-code")
                    .threshold(1)
                    .add_expected_product(
                        ArtifactRuleBuilder::new()
                            .rule("CREATE")
                            .pattern("foo.py")
                            .build()
                            .unwrap(),
                    )
                    .add_key(alice_key.key_id().to_owned())
                    .expected_command("vi".into()),
            )
            .add_step(
                Step::new("package")
                    .threshold(1)
                    .add_expected_material(
                        ArtifactRuleBuilder::new()
                            .rule("MATCH")
                            .pattern("foo.py")
                            .with_products()
                            .from_step("write-code")
                            .build()
                            .unwrap(),
                    )
                    .add_expected_product(
                        ArtifactRuleBuilder::new()
                            .rule("CREATE")
                            .pattern("foo.tar.gz")
                            .build()
                            .unwrap(),
                    )
                    .add_key(bob_key.key_id().to_owned())
                    .expected_command("tar zcvf foo.tar.gz foo.py".into()),
            )
            .add_inspect(
                Inspection::new("inspect_tarball")
                    .add_expected_material(
                        ArtifactRuleBuilder::new()
                            .rule("MATCH")
                            .pattern("foo.tar.gz")
                            .with_products()
                            .from_step("package")
                            .build()
                            .unwrap(),
                    )
                    .add_expected_product(
                        ArtifactRuleBuilder::new()
                            .rule("MATCH")
                            .pattern("foo.py")
                            .with_products()
                            .from_step("write-code")
                            .build()
                            .unwrap(),
                    )
                    .run("inspect_tarball.sh foo.tar.gz".into()),
            )
            .readme("".into())
            .build()
            .unwrap();
        Layout::from(&metadata).unwrap()
    }

    #[test]
    fn serialize_layout() {
        let layout = get_example_layout_metadata();
        let json = json!({
            "_type" : "layout",
            "expires" : "1970-01-01T00:00:00Z",
            "keys" : {
                "e0294a3f17cc8563c3ed5fceb3bd8d3f6bfeeaca499b5c9572729ae015566554": {
                    "keytype": "ed25519",
                    "keyval": {
                        "public": "eb8ac26b5c9ef0279e3be3e82262a93bce16fe58ee422500d38caf461c65a3b6",
                    },
                    "scheme": "ed25519"
                },
                "3e26343b3a7907b5652dec86222e8fd60e456ebbb6fe4875a1f4281ffd5bd9ae" : {
                    "keytype": "rsa",
                    "keyval": {
                        "public": "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA91-6CJmBzrb6ODSXPvVKh9IVvDkD63d5_wHawj1ZB22Y0R7A7b8lRl7IqJJ3TcZO8W2zFfeRuPFlghQs-O7hA6XiRr4mlD1dLItk-p93E0vgY-_Jj4I09LObgA2ncGw_bUlYt3fB5tbmnojQyhrQwUQvBxOqI3nSglg02mCdQRWpPzerGxItOIQkmU2TsqTg7TZ8lnSUbAsFuMebnA2dJ2hzeou7ZGsyCJj_6O0ORVF37nLZiOFF8EskKVpUJuoLWopEA2c09YDgFWHEPTIoGNWB2l_qyX7HTk1wf-WK_Wnn3nerzdEhY9dH-U0uH7tOBBVCyEKxUqXDGpzuLSxOGBpJXa3TTqLHJWIOzhIjp5J3rV93aeSqemU38KjguZzdwOMO5lRsFco5gaFS9aNLLXtLd4ZgXaxB3vYqFDhvZCx4IKrsYEc_Nr8ubLwyQ8WHeS7v8FpIT7H9AVNDo9BMZpnmdTc5Lxi15_TulmswIIgjDmmIqujUqyHN27u7l6bZJlcn8lQdYMm4eJr2o-JtdloTwm7Cv_gKkhZ5tdO5c_219UYBnKaGF8No1feEHirm5mdvwpngCxdFMZMbfmUAfzPeVPkXE-LR0lsLGnMlXKG5vKFcQpCXW9iwJ4pZl7j12wLwiWyLDQtsIxiG6SdsALPkWf0mnfBaVj_Q4FNkJBECAwEAAQ==",
                    },
                    "keyid_hash_algorithms" : [
                        "sha256",
                        "sha512"
                    ],
                    "scheme": "rsassa-pss-sha256"
                }
            },
            "steps" : [
                {
                  "_name": "write-code",
                  "threshold": 1,
                  "expected_materials": [ ],
                  "expected_products": [
                      ["CREATE", "foo.py"]
                  ],
                  "pubkeys": [
                      "e0294a3f17cc8563c3ed5fceb3bd8d3f6bfeeaca499b5c9572729ae015566554"
                  ],
                  "expected_command": "vi"
                },
                {
                  "_name": "package",
                  "threshold": 1,
                  "expected_materials": [
                      ["MATCH", "foo.py", "WITH", "PRODUCTS", "FROM", "write-code"]
                  ],
                  "expected_products": [
                      ["CREATE", "foo.tar.gz"]
                  ],
                  "pubkeys": [
                      "3e26343b3a7907b5652dec86222e8fd60e456ebbb6fe4875a1f4281ffd5bd9ae"
                  ],
                  "expected_command": "tar zcvf foo.tar.gz foo.py"
                }],
              "inspect": [
                {
                  "_name": "inspect_tarball",
                  "expected_materials": [
                      ["MATCH", "foo.tar.gz", "WITH", "PRODUCTS", "FROM", "package"]
                  ],
                  "expected_products": [
                      ["MATCH", "foo.py", "WITH", "PRODUCTS", "FROM", "write-code"]
                  ],
                  "run": "inspect_tarball.sh foo.tar.gz"
                }
              ],
              "readme": ""
        });

        let json_serialize = serde_json::to_value(&layout).unwrap();
        assert_eq!(json, json_serialize, "{:#?} != {:#?}", json, json_serialize);
    }

    #[test]
    fn deserialize_layout() {
        let json = r#"{
        "_type" : "layout",
        "expires" : "1970-01-01T00:00:00Z",
        "keys" : {
            "e0294a3f17cc8563c3ed5fceb3bd8d3f6bfeeaca499b5c9572729ae015566554": {
                "keytype": "ed25519",
                "keyval": {
                    "public": "eb8ac26b5c9ef0279e3be3e82262a93bce16fe58ee422500d38caf461c65a3b6"
                },
                "scheme": "ed25519"
            },
            "3e26343b3a7907b5652dec86222e8fd60e456ebbb6fe4875a1f4281ffd5bd9ae" : {
                "keytype": "rsa",
                "keyval": {
                    "public": "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA91-6CJmBzrb6ODSXPvVKh9IVvDkD63d5_wHawj1ZB22Y0R7A7b8lRl7IqJJ3TcZO8W2zFfeRuPFlghQs-O7hA6XiRr4mlD1dLItk-p93E0vgY-_Jj4I09LObgA2ncGw_bUlYt3fB5tbmnojQyhrQwUQvBxOqI3nSglg02mCdQRWpPzerGxItOIQkmU2TsqTg7TZ8lnSUbAsFuMebnA2dJ2hzeou7ZGsyCJj_6O0ORVF37nLZiOFF8EskKVpUJuoLWopEA2c09YDgFWHEPTIoGNWB2l_qyX7HTk1wf-WK_Wnn3nerzdEhY9dH-U0uH7tOBBVCyEKxUqXDGpzuLSxOGBpJXa3TTqLHJWIOzhIjp5J3rV93aeSqemU38KjguZzdwOMO5lRsFco5gaFS9aNLLXtLd4ZgXaxB3vYqFDhvZCx4IKrsYEc_Nr8ubLwyQ8WHeS7v8FpIT7H9AVNDo9BMZpnmdTc5Lxi15_TulmswIIgjDmmIqujUqyHN27u7l6bZJlcn8lQdYMm4eJr2o-JtdloTwm7Cv_gKkhZ5tdO5c_219UYBnKaGF8No1feEHirm5mdvwpngCxdFMZMbfmUAfzPeVPkXE-LR0lsLGnMlXKG5vKFcQpCXW9iwJ4pZl7j12wLwiWyLDQtsIxiG6SdsALPkWf0mnfBaVj_Q4FNkJBECAwEAAQ=="
                },
                "keyid_hash_algorithms" : [
                    "sha256",
                    "sha512"
                ],
                "scheme": "rsassa-pss-sha256"
            }
        },
        "steps" : [
            {
              "_name": "write-code",
              "threshold": 1,
              "expected_materials": [ ],
              "expected_products": [
                  ["CREATE", "foo.py"]
              ],
              "pubkeys": [
                  "e0294a3f17cc8563c3ed5fceb3bd8d3f6bfeeaca499b5c9572729ae015566554"
              ],
              "expected_command": "vi"
            },
            {
              "_name": "package",
              "threshold": 1,
              "expected_materials": [
                  ["MATCH", "foo.py", "WITH", "PRODUCTS", "FROM", "write-code"]
              ],
              "expected_products": [
                  ["CREATE", "foo.tar.gz"]
              ],
              "pubkeys": [
                  "3e26343b3a7907b5652dec86222e8fd60e456ebbb6fe4875a1f4281ffd5bd9ae"
              ],
              "expected_command": "tar zcvf foo.tar.gz foo.py"
            }],
          "inspect": [
            {
              "_name": "inspect_tarball",
              "expected_materials": [
                  ["MATCH", "foo.tar.gz", "WITH", "PRODUCTS", "FROM", "package"]
              ],
              "expected_products": [
                  ["MATCH", "foo.py", "WITH", "PRODUCTS", "FROM", "write-code"]
              ],
              "run": "inspect_tarball.sh foo.tar.gz"
            }
          ],
          "readme": ""
        }"#;

        let layout = get_example_layout_metadata();
        let layout_parse: Layout = serde_json::from_str(json).unwrap();
        assert_eq!(layout, layout_parse);
    }
}
