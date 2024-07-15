use serde::{Deserialize, Serialize};

use crate::interchange::DataInterchange;
use crate::Result;
use crate::{crypto::Signature, interchange::Json};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeFile {
    payload: String,
    payload_type: String,
    signatures: Vec<Signature>,
}

impl EnvelopeFile {
    #[allow(dead_code)]
    // TODO: remove #[allow(dead_code)] after metadata deploy
    pub fn new(
        payload: String,
        payload_type: String,
        signatures: Vec<Signature>,
    ) -> Self {
        Self {
            payload,
            payload_type,
            signatures,
        }
    }

    /// standard serialize for EnvelopeFile
    #[allow(dead_code)]
    // TODO: remove #[allow(dead_code)] after metadata deploy
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Json::canonicalize(&Json::serialize(self)?)
    }

    /// standard deserialize for EnvelopeFile
    #[allow(dead_code)]
    // TODO: remove #[allow(dead_code)] after metadata deploy
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let ret: Self = serde_json::from_slice(bytes)?;
        Ok(ret)
    }

    #[allow(dead_code)]
    // TODO: remove #[allow(dead_code)] after metadata deploy
    pub fn signatures(&self) -> &Vec<Signature> {
        &self.signatures
    }

    #[allow(dead_code)]
    // TODO: remove #[allow(dead_code)] after metadata deploy
    pub fn payload(&self) -> &String {
        &self.payload
    }

    #[allow(dead_code)]
    // TODO: remove #[allow(dead_code)] after metadata deploy
    pub fn payload_type(&self) -> &String {
        &self.payload_type
    }
}

#[cfg(test)]
mod test_envelope_file {
    use std::str;

    use once_cell::sync::Lazy;

    use super::EnvelopeFile;
    // TODO: change to mock test use mockall
    use crate::crypto::Signature;

    pub struct EnvelopeFileTuple<'a> {
        name: String,
        payload: String,
        payload_type: String,
        signatures: Vec<Signature>,
        packet: &'a str,
    }

    pub static SERIALIZE_DATAS: Lazy<Vec<EnvelopeFileTuple>> = Lazy::new(
        || {
            vec![
            EnvelopeFileTuple {
                name: "blank_test".to_string(),
                payload: "114514".to_string(),
                payload_type: "link".to_string(),
                signatures: Vec::new(),
                packet: "{\"payload\":\"114514\",\"payload_type\":\"link\",\"signatures\":[]}",
            },
            EnvelopeFileTuple {
                name: "blank_test".to_string(),
                payload: "in-toto-rs".to_string(),
                payload_type: "https://in-toto.io/statement/v0.1".to_string(),
                signatures: Vec::new(),
                packet: "{\"payload\":\"in-toto-rs\",\"payload_type\":\"https://in-toto.io/statement/v0.1\",\"signatures\":[]}",
            },
        ]
        },
    );

    #[test]
    fn serialize_link() {
        for item in SERIALIZE_DATAS.iter() {
            let envelope_file = EnvelopeFile::new(
                item.payload.clone(),
                item.payload_type.clone(),
                item.signatures.clone(),
            );
            let bytes = envelope_file.to_bytes().unwrap();

            let real = str::from_utf8(&bytes).unwrap();
            let right = item.packet;
            assert_eq!(real, right, "Assert serialize unequal {}", item.name);
        }
    }

    #[test]
    fn deserialize_link() {
        for item in SERIALIZE_DATAS.iter() {
            let envelope_file =
                EnvelopeFile::from_bytes(item.packet.as_bytes()).unwrap();
            assert_eq!(
                envelope_file.payload(),
                &item.payload,
                "Assert deserialize unequal {} for {} and {}",
                item.name,
                envelope_file.payload(),
                &item.payload
            );
            assert_eq!(
                envelope_file.payload_type(),
                &item.payload_type,
                "Assert deserialize unequal {} for {} and {}",
                item.name,
                envelope_file.payload_type(),
                &item.payload_type,
            );
            assert_eq!(
                envelope_file.signatures(),
                &item.signatures,
                "Assert deserialize unequal {} for {:?} and {:?}",
                item.name,
                envelope_file.signatures(),
                &item.signatures,
            );
        }
    }
}
