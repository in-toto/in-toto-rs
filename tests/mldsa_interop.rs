//! Cross-implementation interop for ML-DSA / TAP 21.
//!
//! The fixtures in `tests/data/mldsa/` are produced by securesystemslib (see
//! `generate_fixtures.py`). These tests pin the parts of the wire format that
//! both implementations must agree on: the keyid, the SPKI/PEM encoding of the
//! public key, and the TAP 21 pre-signing byte string.
//!
//! Note that signature *bytes* are deliberately not compared: `ml-dsa`'s
//! `Signer` impl is deterministic while pyca/cryptography signs randomized.
//! Both are valid ML-DSA, so interop is checked by cross-verification.

#![cfg(feature = "mldsa")]

use data_encoding::HEXLOWER;
use in_toto::crypto::{
    KeyId, PrivateKey, PublicKey, Signature, SignatureScheme, SignatureValue,
};
use serde_json::Value;

const FIXTURE: &str = include_str!("data/mldsa/mldsa65_fixture.json");
const PRIVATE_PEM: &str = include_str!("data/mldsa/mldsa65_private.pem");
const PUBLIC_PEM: &str = include_str!("data/mldsa/mldsa65_public.pem");

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("fixture is valid json")
}

fn private_key() -> PrivateKey {
    let der = pem::parse(PRIVATE_PEM).expect("private key is valid pem");
    PrivateKey::from_pkcs8(der.contents(), SignatureScheme::MlDsa65V1)
        .expect("securesystemslib PKCS#8 key parses")
}

/// The keyid must match securesystemslib byte for byte, or metadata signed by
/// one implementation cannot be looked up by the other.
#[test]
fn keyid_matches_securesystemslib() {
    let f = fixture();
    let expected = f["keyid"].as_str().unwrap();

    let key = private_key();
    let expected: KeyId = expected.parse().expect("fixture keyid parses");
    assert_eq!(
        key.key_id(),
        &expected,
        "keyid disagrees with securesystemslib"
    );
}

/// The public key must serialise to the same PEM securesystemslib emits,
/// including the absence of NULL AlgorithmIdentifier parameters.
#[test]
fn public_key_pem_roundtrips() {
    let key = private_key();
    let spki = key.public().as_spki().expect("spki encodes");

    let expected_der = pem::parse(PUBLIC_PEM).expect("public key is valid pem");
    assert_eq!(
        spki,
        expected_der.contents(),
        "SPKI DER differs from securesystemslib's"
    );

    // ...and parsing that PEM back yields the same key.
    let parsed =
        PublicKey::from_pem_spki(PUBLIC_PEM, SignatureScheme::MlDsa65V1)
            .expect("public pem parses");
    assert_eq!(&parsed, key.public());
}

/// We must reconstruct exactly the bytes securesystemslib signs.
#[test]
fn presign_string_matches_tap21() {
    let f = fixture();
    let msg = f["msg_utf8"].as_str().unwrap().as_bytes();
    let expected = f["presign_hex"].as_str().unwrap();

    // b"tuf" || 0x01 || SHA-512(msg)
    let mut expected_bytes = Vec::new();
    expected_bytes.extend_from_slice(b"tuf");
    expected_bytes.push(0x01);
    expected_bytes.extend_from_slice(
        ring::digest::digest(&ring::digest::SHA512, msg).as_ref(),
    );

    assert_eq!(HEXLOWER.encode(&expected_bytes), expected);
}

/// The headline check: a signature made by securesystemslib verifies here.
#[test]
fn verifies_securesystemslib_signature() {
    let f = fixture();
    let msg = f["msg_utf8"].as_str().unwrap().as_bytes();
    let sig_bytes = HEXLOWER
        .decode(f["signature_hex"].as_str().unwrap().as_bytes())
        .expect("signature is hex");

    let key = private_key();
    let signature = Signature {
        key_id: key.key_id().clone(),
        value: SignatureValue::new(sig_bytes),
    };

    key.public()
        .verify(msg, &signature)
        .expect("securesystemslib signature must verify");
}

#[test]
fn sign_verify_roundtrip() {
    let key = private_key();
    let msg = b"rebuilderd attestation";

    let sig = key.sign(msg).expect("signing works");
    key.public()
        .verify(msg, &sig)
        .expect("own signature verifies");
}

#[test]
fn rejects_tampered_message() {
    let key = private_key();
    let sig = key.sign(b"original").expect("signing works");
    assert!(key.public().verify(b"tampered", &sig).is_err());
}

#[test]
fn rejects_wrong_parameter_set() {
    // The key is ML-DSA-65; claiming -87 must fail rather than silently
    // verifying against the wrong parameter set.
    let der = pem::parse(PRIVATE_PEM).unwrap();
    assert!(
        PrivateKey::from_pkcs8(der.contents(), SignatureScheme::MlDsa87V1)
            .is_err()
    );
    assert!(
        PublicKey::from_pem_spki(PUBLIC_PEM, SignatureScheme::MlDsa87V1)
            .is_err()
    );
}

#[test]
fn generated_keys_work() {
    let der = PrivateKey::new_mldsa(SignatureScheme::MlDsa44V1)
        .expect("keygen works");
    let key = PrivateKey::from_pkcs8(&der, SignatureScheme::MlDsa44V1)
        .expect("generated key parses");
    let sig = key.sign(b"hello").expect("signing works");
    key.public().verify(b"hello", &sig).expect("verifies");
}
