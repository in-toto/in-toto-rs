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

/// Build the suite once per ML-DSA parameter set.
///
/// `$wrong` is a different parameter set, used to check that a key is never
/// accepted under a scheme its OID disagrees with.
macro_rules! interop_suite {
    ($name:ident, $scheme:expr, $wrong:expr, $dir:literal) => {
        mod $name {
            use super::*;

            const FIXTURE: &str =
                include_str!(concat!("data/mldsa/", $dir, "_fixture.json"));
            const PRIVATE_PEM: &str =
                include_str!(concat!("data/mldsa/", $dir, "_private.pem"));
            const PUBLIC_PEM: &str =
                include_str!(concat!("data/mldsa/", $dir, "_public.pem"));

            fn fixture() -> Value {
                serde_json::from_str(FIXTURE).expect("fixture is valid json")
            }

            fn private_key() -> PrivateKey {
                let der =
                    pem::parse(PRIVATE_PEM).expect("private key is valid pem");
                PrivateKey::from_pkcs8(der.contents(), $scheme)
                    .expect("securesystemslib PKCS#8 key parses")
            }

            /// The keyid must match securesystemslib byte for byte, or metadata
            /// signed by one implementation cannot be looked up by the other.
            #[test]
            fn keyid_matches_securesystemslib() {
                let f = fixture();
                let expected: KeyId = f["keyid"]
                    .as_str()
                    .unwrap()
                    .parse()
                    .expect("fixture keyid parses");

                assert_eq!(
                    private_key().key_id(),
                    &expected,
                    "keyid disagrees with securesystemslib"
                );
            }

            /// The scheme in the fixture must be the one we claim to test.
            #[test]
            fn fixture_scheme_matches() {
                let f = fixture();
                let scheme: SignatureScheme =
                    serde_json::from_value(f["scheme"].clone())
                        .expect("scheme parses");
                assert_eq!(scheme, $scheme);
            }

            /// The public key must serialise to the same PEM securesystemslib
            /// emits, including the absence of NULL AlgorithmIdentifier params.
            #[test]
            fn public_key_pem_roundtrips() {
                let key = private_key();
                let spki = key.public().as_spki().expect("spki encodes");

                let expected =
                    pem::parse(PUBLIC_PEM).expect("public key is valid pem");
                assert_eq!(
                    spki,
                    expected.contents(),
                    "SPKI DER differs from securesystemslib's"
                );

                let parsed = PublicKey::from_pem_spki(PUBLIC_PEM, $scheme)
                    .expect("public pem parses");
                assert_eq!(&parsed, key.public());
            }

            /// We must reconstruct exactly the bytes securesystemslib signs.
            #[test]
            fn presign_string_matches_tap21() {
                let f = fixture();
                let msg = f["msg_utf8"].as_str().unwrap().as_bytes();

                // b"tuf" || 0x01 || SHA-512(msg)
                let mut expected = Vec::new();
                expected.extend_from_slice(b"tuf");
                expected.push(0x01);
                expected.extend_from_slice(
                    ring::digest::digest(&ring::digest::SHA512, msg).as_ref(),
                );

                assert_eq!(
                    HEXLOWER.encode(&expected),
                    f["presign_hex"].as_str().unwrap()
                );
            }

            /// The headline check: a securesystemslib signature verifies here.
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

            /// Claiming the wrong parameter set must fail loudly rather than
            /// verifying against a mismatched key.
            #[test]
            fn rejects_wrong_parameter_set() {
                let der = pem::parse(PRIVATE_PEM).unwrap();
                assert!(
                    PrivateKey::from_pkcs8(der.contents(), $wrong).is_err()
                );
                assert!(PublicKey::from_pem_spki(PUBLIC_PEM, $wrong).is_err());
            }

            #[test]
            fn generated_keys_work() {
                let der = PrivateKey::new_mldsa($scheme).expect("keygen works");
                let key = PrivateKey::from_pkcs8(&der, $scheme)
                    .expect("generated key parses");
                let sig = key.sign(b"hello").expect("signing works");
                key.public().verify(b"hello", &sig).expect("verifies");
            }
        }
    };
}

interop_suite!(
    mldsa44,
    SignatureScheme::MlDsa44V1,
    SignatureScheme::MlDsa65V1,
    "mldsa44"
);
interop_suite!(
    mldsa65,
    SignatureScheme::MlDsa65V1,
    SignatureScheme::MlDsa87V1,
    "mldsa65"
);
interop_suite!(
    mldsa87,
    SignatureScheme::MlDsa87V1,
    SignatureScheme::MlDsa44V1,
    "mldsa87"
);

/// A signature from one parameter set must not verify under another.
#[test]
fn signatures_do_not_cross_parameter_sets() {
    let der = pem::parse(include_str!("data/mldsa/mldsa65_private.pem"))
        .expect("valid pem");
    let key =
        PrivateKey::from_pkcs8(der.contents(), SignatureScheme::MlDsa65V1)
            .expect("key parses");
    let sig = key.sign(b"payload").expect("signing works");

    let other = pem::parse(include_str!("data/mldsa/mldsa87_private.pem"))
        .expect("valid pem");
    let other =
        PrivateKey::from_pkcs8(other.contents(), SignatureScheme::MlDsa87V1)
            .expect("key parses");

    assert!(other.public().verify(b"payload", &sig).is_err());
}
