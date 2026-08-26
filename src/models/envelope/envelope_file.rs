use data_encoding::BASE64;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::{KeyId, PrivateKey, PublicKey, Signature, SignatureValue};
use crate::models::envelope::DSSEVersion;
use crate::Result;
use crate::{Error, Result as InTotoResult};

/// A DSSE envelope.
///
/// The signature is over the Pre-Authentication Encoding of the payload and its
/// type, not over the payload itself, so a verifier never has to parse
/// untrusted input to check a signature, and the payload type is authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeFile {
    payload: Vec<u8>,
    payload_type: String,
    signatures: Vec<Signature>,
}

impl EnvelopeFile {
    /// Assemble an envelope from an existing set of signatures.
    pub fn new(
        payload: Vec<u8>,
        payload_type: String,
        signatures: Vec<Signature>,
    ) -> Self {
        Self {
            payload,
            payload_type,
            signatures,
        }
    }

    /// Sign a payload with each of `private_keys`.
    pub fn sign(
        payload: Vec<u8>,
        payload_type: &str,
        private_keys: &[&PrivateKey],
    ) -> InTotoResult<Self> {
        let pae = DSSEVersion::V1.pack(&payload, payload_type.to_string());

        let mut signatures = Vec::new();
        for key in private_keys {
            signatures.push(key.sign(&pae)?);
        }

        Ok(Self {
            payload,
            payload_type: payload_type.to_string(),
            signatures,
        })
    }

    /// Verify the envelope, returning the payload once `threshold` authorized
    /// keys have signed it.
    pub fn verify<'a, I>(
        &self,
        threshold: u32,
        authorized_keys: I,
    ) -> InTotoResult<&[u8]>
    where
        I: IntoIterator<Item = &'a PublicKey>,
    {
        if threshold < 1 {
            return Err(Error::VerificationFailure(
                "Threshold must be strictly greater than zero".into(),
            ));
        }

        let pae =
            DSSEVersion::V1.pack(&self.payload, self.payload_type.clone());

        let mut signed_by = Vec::new();
        for key in authorized_keys {
            // Each key is checked against its own signature. Duplicate keys
            // must not count twice towards the threshold.
            if signed_by.contains(&key.key_id()) {
                continue;
            }

            let signed = self.signatures.iter().any(|sig| {
                sig.key_id() == key.key_id() && key.verify(&pae, sig).is_ok()
            });

            if signed {
                signed_by.push(key.key_id());
            }
        }

        if (signed_by.len() as u32) < threshold {
            return Err(Error::VerificationFailure(format!(
                "Signature threshold not met: {}/{}",
                signed_by.len(),
                threshold
            )));
        }

        Ok(&self.payload)
    }

    /// Serialize the envelope as DSSE JSON.
    ///
    /// Unlike the in-toto metablock this is not canonicalized: DSSE exists
    /// precisely so that verification does not depend on canonicalization.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Parse a DSSE JSON envelope.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn signatures(&self) -> &Vec<Signature> {
        &self.signatures
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn payload_type(&self) -> &str {
        &self.payload_type
    }
}

/// The wire form.
///
/// DSSE base64-encodes both the payload and each signature, where the in-toto
/// metablock writes signatures as hex -- so `Signature`'s own serde impl cannot
/// be reused here.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeWire {
    payload: String,
    #[serde(rename = "payloadType")]
    payload_type: String,
    signatures: Vec<SignatureWire>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureWire {
    keyid: KeyId,
    sig: String,
}

impl Serialize for EnvelopeFile {
    fn serialize<S: Serializer>(
        &self,
        ser: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        EnvelopeWire {
            payload: BASE64.encode(&self.payload),
            payload_type: self.payload_type.clone(),
            signatures: self
                .signatures
                .iter()
                .map(|sig| SignatureWire {
                    keyid: sig.key_id().clone(),
                    sig: BASE64.encode(sig.value().as_bytes()),
                })
                .collect(),
        }
        .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for EnvelopeFile {
    fn deserialize<D: Deserializer<'de>>(
        de: D,
    ) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as DeserializeError;

        let wire = EnvelopeWire::deserialize(de)?;

        let payload = BASE64.decode(wire.payload.as_bytes()).map_err(|e| {
            DeserializeError::custom(format!(
                "Couldn't decode payload as base64: {:?}",
                e
            ))
        })?;

        let mut signatures = Vec::new();
        for sig in wire.signatures {
            let value = BASE64.decode(sig.sig.as_bytes()).map_err(|e| {
                DeserializeError::custom(format!(
                    "Couldn't decode signature as base64: {:?}",
                    e
                ))
            })?;

            signatures.push(Signature {
                key_id: sig.keyid,
                value: SignatureValue::new(value),
            });
        }

        Ok(EnvelopeFile {
            payload,
            payload_type: wire.payload_type,
            signatures,
        })
    }
}

#[cfg(test)]
mod test_envelope_file {
    use super::*;
    use crate::crypto::KeyType;

    const FIXTURE: &str = include_str!("../../../tests/data/dsse/fixture.json");
    const ENVELOPE: &str =
        include_str!("../../../tests/data/dsse/envelope.json");

    fn fixture() -> serde_json::Value {
        serde_json::from_str(FIXTURE).unwrap()
    }

    fn fixture_key() -> PrivateKey {
        let hex = fixture()["key_ed25519_hex"].as_str().unwrap().to_string();
        let bytes = data_encoding::HEXLOWER.decode(hex.as_bytes()).unwrap();
        PrivateKey::from_ed25519(&bytes).unwrap()
    }

    fn generated_key() -> PrivateKey {
        let der = PrivateKey::new(KeyType::Ed25519).unwrap();
        PrivateKey::from_pkcs8(&der, crate::crypto::SignatureScheme::Ed25519)
            .unwrap()
    }

    /// The keyid has to agree with securesystemslib or signatures cannot be
    /// matched to keys across implementations.
    #[test]
    fn keyid_matches_the_reference_implementation() {
        let expected = fixture()["keyid"].as_str().unwrap().to_string();
        let key = fixture_key();

        assert_eq!(
            format!("{:?}", key.key_id()),
            format!("KeyId(\"{}\")", expected)
        );
    }

    /// The bytes actually signed must match, or nothing else can.
    #[test]
    fn pae_matches_the_reference_implementation() {
        let f = fixture();
        let payload = f["payload_utf8"].as_str().unwrap().as_bytes();
        let payload_type = f["payload_type"].as_str().unwrap().to_string();

        let pae = DSSEVersion::V1.pack(payload, payload_type);

        assert_eq!(
            String::from_utf8(pae).unwrap(),
            f["pae_utf8"].as_str().unwrap()
        );
    }

    /// An envelope written by securesystemslib must parse and verify here.
    #[test]
    fn verifies_a_reference_envelope() {
        let envelope = EnvelopeFile::from_bytes(ENVELOPE.as_bytes()).unwrap();
        let key = fixture_key();

        assert_eq!(
            envelope.payload_type(),
            fixture()["payload_type"].as_str().unwrap()
        );
        assert_eq!(
            envelope.payload(),
            fixture()["payload_utf8"].as_str().unwrap().as_bytes()
        );

        let payload = envelope.verify(1, [key.public()]).unwrap();
        assert_eq!(payload, envelope.payload());
    }

    /// ...and what we write must be byte-identical to what it wrote.
    #[test]
    fn round_trips_a_reference_envelope() {
        let envelope = EnvelopeFile::from_bytes(ENVELOPE.as_bytes()).unwrap();

        let ours: serde_json::Value =
            serde_json::from_slice(&envelope.to_bytes().unwrap()).unwrap();
        let theirs: serde_json::Value = serde_json::from_str(ENVELOPE).unwrap();

        assert_eq!(ours, theirs);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = generated_key();
        let envelope = EnvelopeFile::sign(
            b"the payload".to_vec(),
            "application/vnd.in-toto+json",
            &[&key],
        )
        .unwrap();

        assert_eq!(envelope.verify(1, [key.public()]).unwrap(), b"the payload");
    }

    #[test]
    fn rejects_a_tampered_payload() {
        let key = generated_key();
        let mut envelope =
            EnvelopeFile::sign(b"original".to_vec(), "text/plain", &[&key])
                .unwrap();

        envelope.payload = b"tampered".to_vec();

        assert!(envelope.verify(1, [key.public()]).is_err());
    }

    /// The payload type is authenticated, which is the property the in-toto
    /// metablock lacked: changing it must invalidate the signature.
    #[test]
    fn rejects_a_tampered_payload_type() {
        let key = generated_key();
        let mut envelope = EnvelopeFile::sign(
            b"payload".to_vec(),
            "application/vnd.in-toto+json",
            &[&key],
        )
        .unwrap();

        envelope.payload_type = "text/plain".to_string();

        assert!(envelope.verify(1, [key.public()]).is_err());
    }

    #[test]
    fn rejects_an_unauthorized_key() {
        let key = generated_key();
        let other = generated_key();
        let envelope =
            EnvelopeFile::sign(b"payload".to_vec(), "text/plain", &[&key])
                .unwrap();

        assert!(envelope.verify(1, [other.public()]).is_err());
    }

    #[test]
    fn threshold_counts_distinct_keys() {
        let a = generated_key();
        let b = generated_key();
        let envelope =
            EnvelopeFile::sign(b"payload".to_vec(), "text/plain", &[&a, &b])
                .unwrap();

        assert!(envelope.verify(2, [a.public(), b.public()]).is_ok());
        // the same key twice must not satisfy a threshold of two
        assert!(envelope.verify(2, [a.public(), a.public()]).is_err());
    }
}
