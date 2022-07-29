use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use self::pae_v1::PaeV1;
use crate::{Error, Result};

mod envelope_file;
mod pae_v1;

pub trait DSSEParser {
    fn pae_pack(payload_ver: String, payload: &[u8]) -> Vec<u8>;
    fn pae_unpack(bytes: &[u8]) -> Result<(Vec<u8>, String)>;
}

/// DSSE global packer and unpacker.
#[derive(EnumIter, PartialEq, Eq, Hash, Clone, Copy)]
pub enum DSSEVersion {
    V1,
}

impl DSSEVersion {
    /// Use Pre-Authentication Encoding to pack payload for any version.
    #[allow(dead_code)]
    // TODO: remove #[allow(dead_code)] after metadata deploy
    pub fn pack(&self, payload: &[u8], payload_ver: String) -> Vec<u8> {
        let payload = payload.to_vec();

        match self {
            DSSEVersion::V1 => PaeV1::pae_pack(payload_ver, &payload),
        }
    }

    /// Use Pre-Authentication Encoding to unpack payload for any version.
    pub fn unpack(&self, bytes: &[u8]) -> Result<(Vec<u8>, String)> {
        // Note: if two of the versions is compatible with each other
        // `try_unpack` may failed to find the right version.
        let (payload, payload_ver) = match self {
            DSSEVersion::V1 => PaeV1::pae_unpack(bytes)?,
        };
        Ok((payload, payload_ver))
    }

    /// Use Pre-Authentication Encoding to auto unpack a possible version.
    #[allow(dead_code)]
    // TODO: remove #[allow(dead_code)] after metadata deploy
    pub fn try_unpack(bytes: &[u8]) -> Result<(Vec<u8>, String)> {
        let mut file: Result<(Vec<u8>, String)> =
            Err(Error::Programming("no available DSSE parser".to_string()));
        for method in DSSEVersion::iter() {
            file = method.unpack(bytes);
            if file.is_ok() {
                break;
            }
        }
        file
    }
}

#[cfg(test)]
mod pae_test {
    use once_cell::sync::Lazy;

    pub struct EnvelopeFileTuple {
        pub(crate) name: String,
        pub(crate) inner_payload: &'static str,
        pub(crate) payload_ver: String,
    }

    pub static SERIALIZE_SRC_DATAS: Lazy<Vec<EnvelopeFileTuple>> = Lazy::new(|| {
        vec![
            EnvelopeFileTuple {
                name: "blank_test".to_string(),
                inner_payload: "",
                payload_ver: "link".to_string(),
            },
            EnvelopeFileTuple {
                name: "blank_envelope_naive_test".to_string(),
                inner_payload: "{\"payload\":[],\"payload_type\":\"link\",\"signatures\":[]}",
                payload_ver: "link".to_string(),
            },
            EnvelopeFileTuple {
                name: "blank_envelope_v01_test".to_string(),
                inner_payload: "{\"payload\":[],\"payload_type\":\"link\",\"signatures\":[]}",
                payload_ver: "https://in-toto.io/statement/v0.1".to_string(),
            },
        ]
    });
}
