use std::str;

use super::DSSEParser;
use crate::Error;
use crate::Result;

const PREFIX: &str = "DSSEv1";
const SPLIT: &str = " ";
const SPLIT_U8: u8 = 0x20;

pub struct PaeV1;

/// Extract length and payload from bytes and consume them
///
/// length, SPLIT, next -> (length, next)
fn consume_load_len(raw: &[u8]) -> Result<(usize, &[u8])> {
    let mut iter = raw.splitn(2, |num| *num == SPLIT_U8);
    let length_raw = iter.next().ok_or_else(|| {
        Error::PAEParseFailed(format!(
            "split '{}' failed for {:?}",
            SPLIT,
            raw.to_owned()
        ))
    })?;

    let length =
        str::from_utf8(length_raw)?.parse::<usize>().map_err(|_| {
            Error::PAEParseFailed(format!(
                "parse to int failed for {:?}",
                length_raw
            ))
        })?;
    let next = iter.next().ok_or_else(|| {
        Error::PAEParseFailed(format!(
            "prefix {} strip failed for {:?}",
            PREFIX,
            raw.to_owned()
        ))
    })?;
    Ok((length, next))
}

impl DSSEParser for PaeV1 {
    /// Use Pre-Authentication Encoding to pack payload for DSSE v1.
    fn pae_pack(payload_ver: String, payload: &[u8]) -> Vec<u8> {
        let sig_header: String = format!(
            "{prefix}{split}{payload_ver_len}{split}{payload_ver}{split}{payload_len}{split}",
            prefix = PREFIX,
            split = SPLIT,
            payload_ver_len = payload_ver.len(),
            payload_ver = payload_ver.as_str(),
            payload_len = payload.len(),
        );
        let sig = [sig_header.as_bytes(), payload].concat();
        sig
    }

    /// Use Pre-Authentication Encoding to unpack payload for DSSE v1.
    fn pae_unpack(bytes: &[u8]) -> Result<(Vec<u8>, String)> {
        // Strip prefix + split "DSSEv1 "
        let raw = bytes
            .strip_prefix(format!("{}{}", PREFIX, SPLIT).as_bytes())
            .ok_or_else(|| {
                Error::PAEParseFailed(format!(
                    "prefix {} strip failed for {:?}",
                    PREFIX,
                    bytes.to_owned()
                ))
            })?;

        // Extract payload_ver from bytes
        let (payload_ver_len, raw) = consume_load_len(raw)?;
        let payload_ver = str::from_utf8(&raw[0..payload_ver_len])?
            .parse::<String>()
            .map_err(|_| {
                Error::PAEParseFailed(format!(
                    "parse to string failed for {:?}",
                    raw
                ))
            })?;

        // Extract payload from bytes
        let (payload_len, raw) =
            consume_load_len(&raw[(payload_ver_len + 1)..])?;
        let payload = raw[0..payload_len].to_vec();

        Ok((payload, payload_ver))
    }
}

#[cfg(test)]
mod pae_test {
    use std::collections::HashMap;
    use std::str;

    use once_cell::sync::Lazy;

    use crate::models::envelope::{pae_test::SERIALIZE_SRC_DATAS, DSSEVersion};

    static SERIALIZE_RESULT_DATAS: Lazy<HashMap<String, &str>> = Lazy::new(
        || {
            HashMap::from([
                ("blank_test".to_string(), "DSSEv1 4 link 0 "),
                (
                    "blank_envelope_naive_test".to_string(),
                    "DSSEv1 4 link 52 {\"payload\":[],\"payload_type\":\"link\",\"signatures\":[]}",
                ),
                (
                    "blank_envelope_v01_test".to_string(),
                    "DSSEv1 33 https://in-toto.io/statement/v0.1 52 {\"payload\":[],\"payload_type\":\"link\",\"signatures\":[]}",
                ),
            ])
        },
    );

    #[test]
    fn test_pack() {
        for file_tuple in SERIALIZE_SRC_DATAS.iter() {
            let outer = DSSEVersion::V1.pack(
                file_tuple.inner_payload.as_bytes(),
                file_tuple.payload_ver.to_owned(),
            );

            let real = std::str::from_utf8(&outer).unwrap();
            let right = *SERIALIZE_RESULT_DATAS.get(&file_tuple.name).unwrap();
            assert_eq!(
                real, right,
                "pack assert failed for {}",
                file_tuple.name
            );
        }
    }

    #[test]
    fn test_unpack() {
        for file_tuple in SERIALIZE_SRC_DATAS.iter() {
            let outer = SERIALIZE_RESULT_DATAS
                .get(&file_tuple.name)
                .unwrap()
                .as_bytes()
                .to_vec();

            let (inner, _) = DSSEVersion::V1.unpack(&outer).unwrap();
            let real = str::from_utf8(&inner).unwrap();
            let right = file_tuple.inner_payload;

            assert_eq!(
                real, right,
                "unpack assert failed for {}",
                file_tuple.name
            );
        }
    }
}
