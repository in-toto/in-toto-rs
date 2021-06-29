// FIXME: imports will be relevant for layout expiration
//use chrono::offset::Utc;
//use chrono::prelude::*;

use serde_derive::{Deserialize, Serialize};

use crate::crypto;


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

