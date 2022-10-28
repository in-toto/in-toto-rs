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

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
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
            expires: format_datetime(&meta.expires),
            readme: meta.readme.to_string(),
            keys: meta
                .keys
                .iter()
                .map(|(id, key)| (id.clone(), key.clone()))
                .collect(),
            steps: meta.steps.clone(),
            inspect: meta.inspect.clone(),
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
    use assert_json_diff::assert_json_eq;
    use chrono::{DateTime, NaiveDateTime, Utc};
    use serde_json::json;

    use crate::{crypto::PublicKey, models::layout::format_datetime};

    use super::{
        inspection::Inspection,
        parse_datetime,
        rule::{Artifact, ArtifactRule},
        step::Step,
        Layout, LayoutMetadataBuilder,
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
                    .add_expected_product(ArtifactRule::Create("foo.py".into()))
                    .add_key(alice_key.key_id().to_owned())
                    .expected_command("vi".into()),
            )
            .add_step(
                Step::new("package")
                    .threshold(1)
                    .add_expected_material(ArtifactRule::Match {
                        pattern: "foo.py".into(),
                        in_src: None,
                        with: Artifact::Products,
                        in_dst: None,
                        from: "write-code".into(),
                    })
                    .add_expected_product(ArtifactRule::Create("foo.tar.gz".into()))
                    .add_key(bob_key.key_id().to_owned())
                    .expected_command("tar zcvf foo.tar.gz foo.py".into()),
            )
            .add_inspect(
                Inspection::new("inspect_tarball")
                    .add_expected_material(ArtifactRule::Match {
                        pattern: "foo.tar.gz".into(),
                        in_src: None,
                        with: Artifact::Products,
                        in_dst: None,
                        from: "package".into(),
                    })
                    .add_expected_product(ArtifactRule::Match {
                        pattern: "foo.py".into(),
                        in_src: None,
                        with: Artifact::Products,
                        in_dst: None,
                        from: "write-code".into(),
                    })
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
            "_type": "layout",
            "expires": "1970-01-01T00:00:00Z",
            "readme": "",
            "keys": {
                "59d12f31ee173dbb3359769414e73c120f219af551baefb70aa69414dfba4aaf": {
                    "keytype": "rsa",
                    "scheme": "rsassa-pss-sha256",
                    "keyid_hash_algorithms": [
                        "sha256",
                        "sha512"
                    ],
                    "keyval": {
                        "public": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA91+6CJmBzrb6ODSXPvVK\nh9IVvDkD63d5/wHawj1ZB22Y0R7A7b8lRl7IqJJ3TcZO8W2zFfeRuPFlghQs+O7h\nA6XiRr4mlD1dLItk+p93E0vgY+/Jj4I09LObgA2ncGw/bUlYt3fB5tbmnojQyhrQ\nwUQvBxOqI3nSglg02mCdQRWpPzerGxItOIQkmU2TsqTg7TZ8lnSUbAsFuMebnA2d\nJ2hzeou7ZGsyCJj/6O0ORVF37nLZiOFF8EskKVpUJuoLWopEA2c09YDgFWHEPTIo\nGNWB2l/qyX7HTk1wf+WK/Wnn3nerzdEhY9dH+U0uH7tOBBVCyEKxUqXDGpzuLSxO\nGBpJXa3TTqLHJWIOzhIjp5J3rV93aeSqemU38KjguZzdwOMO5lRsFco5gaFS9aNL\nLXtLd4ZgXaxB3vYqFDhvZCx4IKrsYEc/Nr8ubLwyQ8WHeS7v8FpIT7H9AVNDo9BM\nZpnmdTc5Lxi15/TulmswIIgjDmmIqujUqyHN27u7l6bZJlcn8lQdYMm4eJr2o+Jt\ndloTwm7Cv/gKkhZ5tdO5c/219UYBnKaGF8No1feEHirm5mdvwpngCxdFMZMbfmUA\nfzPeVPkXE+LR0lsLGnMlXKG5vKFcQpCXW9iwJ4pZl7j12wLwiWyLDQtsIxiG6Sds\nALPkWf0mnfBaVj/Q4FNkJBECAwEAAQ==\n-----END PUBLIC KEY-----"
                    }
                },
                "e0294a3f17cc8563c3ed5fceb3bd8d3f6bfeeaca499b5c9572729ae015566554": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {
                        "public": "eb8ac26b5c9ef0279e3be3e82262a93bce16fe58ee422500d38caf461c65a3b6"
                    }
                }
            },
            "steps": [
                {
                  "_type": "step",
                  "name": "write-code",
                  "threshold": 1,
                  "expected_materials": [ ],
                  "expected_products": [
                      ["CREATE", "foo.py"]
                  ],
                  "pubkeys": [
                      "e0294a3f17cc8563c3ed5fceb3bd8d3f6bfeeaca499b5c9572729ae015566554"
                  ],
                  "expected_command": ["vi"]
                },
                {
                  "_type": "step",
                  "name": "package",
                  "threshold": 1,
                  "expected_materials": [
                      ["MATCH", "foo.py", "WITH", "PRODUCTS", "FROM", "write-code"]
                  ],
                  "expected_products": [
                      ["CREATE", "foo.tar.gz"]
                  ],
                  "pubkeys": [
                      "59d12f31ee173dbb3359769414e73c120f219af551baefb70aa69414dfba4aaf"
                  ],
                  "expected_command": ["tar", "zcvf", "foo.tar.gz", "foo.py"]
                }],
              "inspect": [
                {
                  "_type": "inspection",
                  "name": "inspect_tarball",
                  "expected_materials": [
                      ["MATCH", "foo.tar.gz", "WITH", "PRODUCTS", "FROM", "package"]
                  ],
                  "expected_products": [
                      ["MATCH", "foo.py", "WITH", "PRODUCTS", "FROM", "write-code"]
                  ],
                  "run": ["inspect_tarball.sh", "foo.tar.gz"]
                }
            ]
        });

        let json_serialize = serde_json::to_value(&layout).unwrap();
        assert_json_eq!(json, json_serialize);
    }

    #[test]
    fn deserialize_layout() {
        let json = r#"{
            "_type": "layout",
            "expires": "1970-01-01T00:00:00Z",
            "readme": "",
            "keys": {
                "59d12f31ee173dbb3359769414e73c120f219af551baefb70aa69414dfba4aaf": {
                    "keytype": "rsa",
                    "scheme": "rsassa-pss-sha256",
                    "keyid_hash_algorithms": [
                        "sha256",
                        "sha512"
                    ],
                    "keyval": {
                        "public": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA91+6CJmBzrb6ODSXPvVK\nh9IVvDkD63d5/wHawj1ZB22Y0R7A7b8lRl7IqJJ3TcZO8W2zFfeRuPFlghQs+O7h\nA6XiRr4mlD1dLItk+p93E0vgY+/Jj4I09LObgA2ncGw/bUlYt3fB5tbmnojQyhrQ\nwUQvBxOqI3nSglg02mCdQRWpPzerGxItOIQkmU2TsqTg7TZ8lnSUbAsFuMebnA2d\nJ2hzeou7ZGsyCJj/6O0ORVF37nLZiOFF8EskKVpUJuoLWopEA2c09YDgFWHEPTIo\nGNWB2l/qyX7HTk1wf+WK/Wnn3nerzdEhY9dH+U0uH7tOBBVCyEKxUqXDGpzuLSxO\nGBpJXa3TTqLHJWIOzhIjp5J3rV93aeSqemU38KjguZzdwOMO5lRsFco5gaFS9aNL\nLXtLd4ZgXaxB3vYqFDhvZCx4IKrsYEc/Nr8ubLwyQ8WHeS7v8FpIT7H9AVNDo9BM\nZpnmdTc5Lxi15/TulmswIIgjDmmIqujUqyHN27u7l6bZJlcn8lQdYMm4eJr2o+Jt\ndloTwm7Cv/gKkhZ5tdO5c/219UYBnKaGF8No1feEHirm5mdvwpngCxdFMZMbfmUA\nfzPeVPkXE+LR0lsLGnMlXKG5vKFcQpCXW9iwJ4pZl7j12wLwiWyLDQtsIxiG6Sds\nALPkWf0mnfBaVj/Q4FNkJBECAwEAAQ==\n-----END PUBLIC KEY-----"
                    }
                },
                "e0294a3f17cc8563c3ed5fceb3bd8d3f6bfeeaca499b5c9572729ae015566554": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {
                        "public": "eb8ac26b5c9ef0279e3be3e82262a93bce16fe58ee422500d38caf461c65a3b6"
                    }
                }
            },
            "steps": [
                {
                    "_type": "step",
                    "name": "write-code",
                    "threshold": 1,
                    "expected_materials": [],
                    "expected_products": [
                        [
                            "CREATE",
                            "foo.py"
                        ]
                    ],
                    "pubkeys": [
                        "e0294a3f17cc8563c3ed5fceb3bd8d3f6bfeeaca499b5c9572729ae015566554"
                    ],
                    "expected_command": [
                        "vi"
                    ]
                },
                {
                    "_type": "step",
                    "name": "package",
                    "threshold": 1,
                    "expected_materials": [
                        [
                            "MATCH",
                            "foo.py",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "write-code"
                        ]
                    ],
                    "expected_products": [
                        [
                            "CREATE",
                            "foo.tar.gz"
                        ]
                    ],
                    "pubkeys": [
                        "59d12f31ee173dbb3359769414e73c120f219af551baefb70aa69414dfba4aaf"
                    ],
                    "expected_command": [
                        "tar",
                        "zcvf",
                        "foo.tar.gz",
                        "foo.py"
                    ]
                }
            ],
            "inspect": [
                {
                    "_type": "inspection",
                    "name": "inspect_tarball",
                    "expected_materials": [
                        [
                            "MATCH",
                            "foo.tar.gz",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "package"
                        ]
                    ],
                    "expected_products": [
                        [
                            "MATCH",
                            "foo.py",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            "write-code"
                        ]
                    ],
                    "run": [
                        "inspect_tarball.sh",
                        "foo.tar.gz"
                    ]
                }
            ]
        }"#;

        let layout = get_example_layout_metadata();
        let layout_parse: Layout = serde_json::from_str(json).unwrap();
        assert_eq!(layout, layout_parse);
    }
}
