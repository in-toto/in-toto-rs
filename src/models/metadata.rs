//! in-toto metadata.
//! # Metadata & MetadataWrapper
//! Metadata is the top level abstract for both layout metadata and link
//! metadata. Metadata it is devided into two types
//! * enum `MetadataWrapper` is used to do serialize, deserialize and
//! other object unsafe operations.
//! * trait `Metadata` is used to work for trait object.
//! The reason please refer to issue https://github.com/in-toto/in-toto-rs/issues/33
//!
//! # Metablock
//! Metablock is the container for link metadata and layout metadata.
//! Its serialized outcome can work as the content of a link file
//! or a layout file. It provides `MetablockBuilder` for create
//! an instance of Metablock, and methods to verify signatures,
//! create signatures.

use log::{debug, warn};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::str;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::crypto::{KeyId, PrivateKey, PublicKey, Signature};
use crate::error::Error;
use crate::interchange::{DataInterchange, Json};
use crate::Result;

use super::{LayoutMetadata, LinkMetadata};

pub const FILENAME_FORMAT: &str = "{step_name}.{keyid:.8}.link";

#[derive(Debug, Serialize, Deserialize, Hash, PartialEq, Eq, EnumIter, Clone, Copy)]
pub enum MetadataType {
    Layout,
    Link,
}

impl Display for MetadataType {
    fn fmt(&self, fmt: &mut Formatter) -> FmtResult {
        match self {
            MetadataType::Layout => fmt.write_str("layout")?,
            MetadataType::Link => fmt.write_str("link")?,
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(untagged)]
pub enum MetadataWrapper {
    Layout(LayoutMetadata),
    Link(LinkMetadata),
}

impl MetadataWrapper {
    /// Convert from enum `MetadataWrapper` to trait `Metadata`
    pub fn into_trait(self) -> Box<dyn Metadata> {
        match self {
            MetadataWrapper::Layout(layout_meta) => Box::new(layout_meta),
            MetadataWrapper::Link(link_meta) => Box::new(link_meta),
        }
    }

    /// Standard deserialize for MetadataWrapper by its metadata
    pub fn from_bytes(bytes: &[u8], metadata_type: MetadataType) -> Result<Self> {
        match metadata_type {
            MetadataType::Layout => serde_json::from_slice(bytes)
                .map(Self::Layout)
                .map_err(|e| e.into()),
            MetadataType::Link => serde_json::from_slice(bytes)
                .map(Self::Link)
                .map_err(|e| e.into()),
        }
    }

    /// Auto deserialize for MetadataWrapper by any possible metadata.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut metadata: Result<MetadataWrapper> =
            Err(Error::Programming("no available bytes parser".to_string()));
        for typ in MetadataType::iter() {
            metadata = MetadataWrapper::from_bytes(bytes, typ);
            if metadata.is_ok() {
                break;
            }
        }
        metadata
    }

    /// Standard serialize for MetadataWrapper by its metadata
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Json::canonicalize(&Json::serialize(self)?)
    }
}

/// trait for Metadata
pub trait Metadata {
    /// The version of Metadata
    fn typ(&self) -> MetadataType;
    /// Convert from trait `Metadata` to enum `MetadataWrapper`
    fn into_enum(self: Box<Self>) -> MetadataWrapper;
    /// Standard serialize for Metadata
    fn to_bytes(&self) -> Result<Vec<u8>>;
}

/// All signed files (link and layout files) have the format.
/// * `signatures`: A pubkey => signature map. signatures are for the metadata.
/// * `metadata`: <ROLE> dictionary. Also known as signed metadata. e.g., link
/// or layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metablock {
    signatures: Vec<Signature>,
    #[serde(rename = "signed")]
    metadata: MetadataWrapper,
}

impl Metablock {
    /// Create a new Metablock, using data of metadata. And the signatures are
    /// generated by using private-keys to sign the metadata.
    pub fn new(metadata: MetadataWrapper, private_keys: &[&PrivateKey]) -> Result<Self> {
        let raw = metadata.to_bytes()?;

        // sign and collect signatures
        let mut signatures = Vec::new();
        private_keys.iter().try_for_each(|key| -> Result<()> {
            let sig = key.sign(&raw)?;
            signatures.push(sig);
            Ok(())
        })?;

        Ok(Self {
            signatures,
            metadata,
        })
    }

    /// An immutable reference to the signatures.
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// Verify this metadata.
    /// Each signature in the Metablock signed by an authorized key
    /// is a legal signature. Only legal the number signatures is
    /// not less than `threshold`, will return the wrapped Metadata.
    pub fn verify<'a, I>(&self, threshold: u32, authorized_keys: I) -> Result<MetadataWrapper>
    where
        I: IntoIterator<Item = &'a PublicKey>,
    {
        if self.signatures.is_empty() {
            return Err(Error::VerificationFailure(
                "The metadata was not signed with any authorized keys.".into(),
            ));
        }

        if threshold < 1 {
            return Err(Error::VerificationFailure(
                "Threshold must be strictly greater than zero".into(),
            ));
        }

        let authorized_keys = authorized_keys
            .into_iter()
            .map(|k| (k.key_id(), k))
            .collect::<HashMap<&KeyId, &PublicKey>>();

        let raw = self.metadata.to_bytes()?;
        let mut signatures_needed = threshold;

        // Create a key_id->signature map to deduplicate the key_ids.
        let signatures = self
            .signatures
            .iter()
            .map(|sig| (sig.key_id(), sig))
            .collect::<HashMap<&KeyId, &Signature>>();

        // check the signatures, if is signed by an authorized key,
        // signatures_needed - 1

        for (key_id, sig) in signatures {
            match authorized_keys.get(key_id) {
                Some(pub_key) => match pub_key.verify(&raw, sig) {
                    Ok(()) => {
                        debug!("Good signature from key ID {:?}", pub_key.key_id());
                        signatures_needed -= 1;
                    }
                    Err(e) => {
                        warn!("Bad signature from key ID {:?}: {:?}", pub_key.key_id(), e);
                    }
                },
                None => {
                    warn!(
                        "Key ID {:?} was not found in the set of authorized keys.",
                        sig.key_id()
                    );
                }
            }
            if signatures_needed == 0 {
                break;
            }
        }

        if signatures_needed > 0 {
            return Err(Error::VerificationFailure(format!(
                "Signature threshold not met: {}/{}",
                threshold - signatures_needed,
                threshold
            )));
        }

        Ok(self.metadata.clone())
    }
}

/// A helper to build Metablock
pub struct MetablockBuilder {
    signatures: HashMap<KeyId, Signature>,
    metadata: MetadataWrapper,
}

impl MetablockBuilder {
    /// Create a new `MetablockBuilder` from a given `Metadata`.
    pub fn from_metadata(metadata: Box<dyn Metadata>) -> Self {
        Self {
            signatures: HashMap::new(),
            metadata: metadata.into_enum(),
        }
    }

    /// Create a new `MetablockBuilder` from manually serialized metadata to be signed.
    /// Returns an error if `metadata` cannot be parsed into Metadata.
    pub fn from_raw_metadata(raw_metadata: &[u8]) -> Result<Self> {
        let metadata = MetadataWrapper::try_from_bytes(raw_metadata)?;
        Ok(Self {
            signatures: HashMap::new(),
            metadata,
        })
    }

    /// Sign the metadata using the given `private_keys`, replacing any existing signatures with the
    /// same `KeyId`.
    pub fn sign(mut self, private_keys: &[&PrivateKey]) -> Result<Self> {
        let mut signatures = HashMap::new();
        let raw = self.metadata.to_bytes()?;

        private_keys.iter().try_for_each(|key| -> Result<()> {
            let sig = key.sign(&raw)?;
            signatures.insert(sig.key_id().clone(), sig);
            Ok(())
        })?;

        self.signatures = signatures;
        Ok(self)
    }

    /// Construct a new `Metablock` using the included signatures, sorting the signatures by
    /// `KeyId`.
    pub fn build(self) -> Metablock {
        let mut signatures = self
            .signatures
            .into_iter()
            .map(|(_k, v)| v)
            .collect::<Vec<_>>();
        signatures.sort_unstable_by(|a, b| a.key_id().cmp(b.key_id()));

        Metablock {
            signatures,
            metadata: self.metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, str::FromStr};

    use chrono::{DateTime, NaiveDateTime, Utc};
    use serde_json::json;

    use crate::{
        crypto::{PrivateKey, PublicKey},
        models::{
            byproducts::ByProducts,
            inspection::Inspection,
            rule::ArtifactRuleBuilder,
            step::{Command, Step},
            LayoutMetadataBuilder, LinkMetadataBuilder, Metablock, VirtualTargetPath,
        },
    };

    use super::MetablockBuilder;

    const ALICE_PRIVATE_KEY: &'static [u8] = include_bytes!("../../tests/ed25519/ed25519-1");
    const ALICE_PUB_KEY: &'static [u8] = include_bytes!("../../tests/ed25519/ed25519-1.pub");
    const BOB_PUB_KEY: &'static [u8] = include_bytes!("../../tests/rsa/rsa-4096.spki.der");
    const OWNER_PRIVATE_KEY: &'static [u8] = include_bytes!("../../tests/test_metadata/owner.der");

    #[test]
    fn deserialize_layout_metablock() {
        let raw = fs::read("tests/test_metadata/demo.layout").unwrap();
        assert!(serde_json::from_slice::<Metablock>(&raw).is_ok());
    }

    #[test]
    fn deserialize_link_metablock() {
        let raw = fs::read("tests/test_metadata/demo.link").unwrap();
        assert!(serde_json::from_slice::<Metablock>(&raw).is_ok());
    }

    #[test]
    fn serialize_layout_metablock() {
        let alice_public_key = PublicKey::from_ed25519(ALICE_PUB_KEY).unwrap();
        let bob_public_key =
            PublicKey::from_spki(BOB_PUB_KEY, crate::crypto::SignatureScheme::RsaSsaPssSha256)
                .unwrap();
        let owner_private_key = PrivateKey::from_ed25519(OWNER_PRIVATE_KEY).unwrap();
        let layout_metadata = Box::new(
            LayoutMetadataBuilder::new()
                .expires(DateTime::<Utc>::from_utc(
                    NaiveDateTime::from_timestamp(0, 0),
                    Utc,
                ))
                .add_key(alice_public_key.clone())
                .add_key(bob_public_key.clone())
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
                        .expected_command(Command::from_str("vi").unwrap())
                        .add_key(alice_public_key.key_id().to_owned()),
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
                        .expected_command(Command::from_str("tar zcvf foo.tar.gz foo.py").unwrap())
                        .add_key(bob_public_key.key_id().to_owned()),
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
                        .run(Command::from_str("inspect_tarball.sh foo.tar.gz").unwrap()),
                )
                .build()
                .unwrap(),
        );

        let private_keys = vec![&owner_private_key];
        let metablock = MetablockBuilder::from_metadata(layout_metadata)
            .sign(&private_keys)
            .unwrap()
            .build();

        let serialized = serde_json::to_value(&metablock).unwrap();
        let expected = json!({
            "signatures": [
                {
                    "keyid": "64786e5921b589af1ca1bf5767087bf201806a9b3ce2e6856c903682132bd1dd",
                    "sig": "0c2c5bb8fb58ccbb644e17bfbda0b754cc13f71ddb5ae4be1fff7ad7ec5c94543bec3818b0c45c4a9dd17545382b4ec6d9fcc71366be08c131505981ca415d04"
                }
            ],
            "signed": {
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
                        "threshold": 1,
                        "_name": "write-code",
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
                        "expected_command": "vi"
                    },
                    {
                        "threshold": 1,
                        "_name": "package",
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
                        "expected_command": "tar zcvf foo.tar.gz foo.py"
                    }
                ],
                "inspect": [
                    {
                        "_name": "inspect_tarball",
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
                        "run": "inspect_tarball.sh foo.tar.gz"
                    }
                ]
            }
        });
        assert_eq!(expected, serialized);
    }

    #[test]
    fn serialize_link_metablock() {
        let link_metadata = LinkMetadataBuilder::new()
            .name("".into())
            .add_product(VirtualTargetPath::new("tests/test_link/foo.tar.gz".into()).unwrap())
            .byproducts(
                ByProducts::new()
                    .set_return_value(0)
                    .set_stderr("a foo.py\n".into())
                    .set_stdout("".into()),
            )
            .command(Command::from("tar zcvf foo.tar.gz foo.py"))
            .build()
            .unwrap();
        let alice_public_key = PrivateKey::from_ed25519(ALICE_PRIVATE_KEY).unwrap();
        let private_keys = vec![&alice_public_key];
        let metablock = MetablockBuilder::from_metadata(Box::new(link_metadata))
            .sign(&private_keys)
            .unwrap()
            .build();
        let serialized = serde_json::to_value(&metablock).unwrap();
        let expected = json!({
            "signed" : {
                "_type": "link",
                "name": "",
                "materials": {},
                "products": {
                    "tests/test_link/foo.tar.gz": {
                        "sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e6936c1e5aabb7c98514f355"
                    }
                },
                "byproducts": {
                    "return-value": 0,
                    "stderr": "a foo.py\n",
                    "stdout": ""
                },
                "command": "tar zcvf foo.tar.gz foo.py",
                "environment": null
            },
            "signatures" : [{
                "keyid" : "e0294a3f17cc8563c3ed5fceb3bd8d3f6bfeeaca499b5c9572729ae015566554",
                "sig": "becef72a0b9c645b3b97034434d06eca50ee811adcb382162d7b22db66732ecfa9b6dfec078a2dddf7495e92c466950a97cbafdc8847dff022f02eff94ea950e"
            }]
        });
        assert_eq!(expected, serialized);
    }

    #[test]
    fn verify_signatures_of_metablock() {
        let link_metadata = LinkMetadataBuilder::new()
            .name("".into())
            .add_product(VirtualTargetPath::new("tests/test_link/foo.tar.gz".into()).unwrap())
            .byproducts(
                ByProducts::new()
                    .set_return_value(0)
                    .set_stderr("a foo.py\n".into())
                    .set_stdout("".into()),
            )
            .command(Command::from("tar zcvf foo.tar.gz foo.py"))
            .build()
            .unwrap();
        let alice_public_key = PrivateKey::from_ed25519(ALICE_PRIVATE_KEY).unwrap();
        let private_keys = vec![&alice_public_key];
        let metablock = MetablockBuilder::from_metadata(Box::new(link_metadata))
            .sign(&private_keys)
            .unwrap()
            .build();

        let public_key = PublicKey::from_ed25519(ALICE_PUB_KEY).unwrap();
        let authorized_keys = vec![&public_key];
        assert!(metablock.verify(1, authorized_keys).is_ok());
    }
}
