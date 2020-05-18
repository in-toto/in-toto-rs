// FIXME: imports will be relevant for layout expiration
//use chrono::offset::Utc;
//use chrono::prelude::*;

use serde_derive::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

use crate::crypto;
use crate::error::Error;
use crate::metadata::{self, Metadata};
use crate::Result;

// FIXME, we need to tag a spec
const SPEC_VERSION: &str = "0.9-dev";

// FIXME: methods will be relevant for layout expiration
// fn parse_datetime(ts: &str) -> Result<DateTime<Utc>> {
//     Utc.datetime_from_str(ts, "%FT%TZ")
//         .map_err(|e| Error::Encoding(format!("Can't parse DateTime: {:?}", e)))
// }
// 
// fn format_datetime(ts: &DateTime<Utc>) -> String {
//     format!(
//         "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
//         ts.year(),
//         ts.month(),
//         ts.day(),
//         ts.hour(),
//         ts.minute(),
//         ts.second()
//     )
// }

#[derive(Debug, Serialize, Deserialize)]
pub struct Link {
    #[serde(rename = "_type")]
    typ: metadata::Role,
    name: String,
    materials: BTreeMap<metadata::VirtualTargetPath, metadata::TargetDescription>,
    products: BTreeMap<metadata::VirtualTargetPath, metadata::TargetDescription>,
    env: BTreeMap<String, String>,
    byproducts: BTreeMap<String, String>,

}

impl Link {
    pub fn from(meta: &metadata::LinkMetadata) -> Result<Self> {
        Ok(Link {
            typ: metadata::Role::Link,
            name: meta.name().to_string(),
            materials: (*meta.materials()).clone(),
            products: (*meta.products()).clone(),
            env: (*meta.env()).clone(),
            byproducts: (*meta.byproducts()).clone()
        })
    }

    pub fn try_into(self) -> Result<metadata::LinkMetadata > {
        if self.typ != metadata::Role::Link {
            return Err(Error::Encoding(format!(
                "Attempted to decode link metdata labeled as {:?}",
                self.typ
            )));
        }

        metadata::LinkMetadata::new(
            self.name,
            self.materials,
            self.products,
            self.env,
            self.byproducts
        )
    }
}


#[derive(Debug, Serialize, Deserialize)]
struct RoleDefinitions {
    root: metadata::RoleDefinition,
}

#[derive(Serialize, Deserialize)]
pub struct RoleDefinition {
    threshold: u32,
    #[serde(rename = "keyids")]
    key_ids: Vec<crypto::KeyId>,
}

impl RoleDefinition {
    pub fn from(role: &metadata::RoleDefinition) -> Result<Self> {
        let key_ids = role
            .key_ids()
            .iter()
            .cloned()
            .collect::<Vec<crypto::KeyId>>();

        Ok(RoleDefinition {
            threshold: role.threshold(),
            key_ids,
        })
    }

    pub fn try_into(self) -> Result<metadata::RoleDefinition> {
        let vec_len = self.key_ids.len();
        if vec_len < 1 {
            return Err(Error::Encoding(
                "Role defined with no assoiciated key IDs.".into(),
            ));
        }

        let mut seen = HashSet::new();
        let mut dupes = 0;
        for key_id in self.key_ids.iter() {
            if !seen.insert(key_id) {
                dupes += 1;
            }
        }

        if dupes != 0 {
            return Err(Error::Encoding(format!(
                "Found {} duplicate key IDs.",
                dupes
            )));
        }

        Ok(metadata::RoleDefinition::new(self.threshold, self.key_ids)?)
    }
}


#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    keytype: crypto::KeyType,
    scheme: crypto::SignatureScheme,
    #[serde(skip_serializing_if = "Option::is_none")]
    keyid_hash_algorithms: Option<Vec<String>>,
    keyval: PublicKeyValue,
}

impl PublicKey {
    pub fn new(
        keytype: crypto::KeyType,
        scheme: crypto::SignatureScheme,
        keyid_hash_algorithms: Option<Vec<String>>,
        public_key: String,
    ) -> Self {
        PublicKey {
            keytype,
            scheme,
            keyid_hash_algorithms,
            keyval: PublicKeyValue { public: public_key },
        }
    }

    pub fn public_key(&self) -> &str {
        &self.keyval.public
    }

    pub fn scheme(&self) -> &crypto::SignatureScheme {
        &self.scheme
    }

    pub fn keytype(&self) -> &crypto::KeyType {
        &self.keytype
    }

    pub fn keyid_hash_algorithms(&self) -> &Option<Vec<String>> {
        &self.keyid_hash_algorithms
    }
}

#[derive(Serialize, Deserialize)]
pub struct PublicKeyValue {
    public: String,
}


#[derive(Serialize, Deserialize)]
pub struct ArtifactHash {
    hashes: BTreeMap<crypto::HashAlgorithm, crypto::HashValue>,
}

impl ArtifactHash {
    pub fn from(description: &metadata::ArtifactHash) -> ArtifactHash {
        ArtifactHash {
            hashes: description
                .hashes()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
    }

    pub fn try_into(self) -> Result<metadata::ArtifactHash> {
        metadata::ArtifactHash::new(
            self.hashes.into_iter().collect(),
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct TargetDescription {
    hashes: BTreeMap<crypto::HashAlgorithm, crypto::HashValue>,
}

impl TargetDescription {
    pub fn from(description: &metadata::TargetDescription) -> TargetDescription {
        TargetDescription {
            hashes: description
                .hashes()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
    }

    pub fn try_into(self) -> Result<metadata::TargetDescription> {
        metadata::TargetDescription::new(
            self.hashes.into_iter().collect(),
        )
    }
}

/// Custom deserialize to reject duplicate keys.
mod deserialize_reject_duplicates {
    use serde::de::{Deserialize, Deserializer, Error, MapAccess, Visitor};
    use std::collections::BTreeMap;
    use std::fmt;
    use std::marker::PhantomData;
    use std::result::Result;

    pub fn deserialize<'de, K, V, D>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
    where
        K: Deserialize<'de> + Ord,
        V: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        struct BTreeVisitor<K, V> {
            marker: PhantomData<(K, V)>,
        };

        impl<'de, K, V> Visitor<'de> for BTreeVisitor<K, V>
        where
            K: Deserialize<'de> + Ord,
            V: Deserialize<'de>,
        {
            type Value = BTreeMap<K, V>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("map")
            }

            fn visit_map<M>(self, mut access: M) -> std::result::Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut map = BTreeMap::new();
                while let Some((key, value)) = access.next_entry()? {
                    if map.insert(key, value).is_some() {
                        return Err(M::Error::custom("Cannot have duplicate keys"));
                    }
                }
                Ok(map)
            }
        }

        deserializer.deserialize_map(BTreeVisitor {
            marker: PhantomData,
        })
    }
}
