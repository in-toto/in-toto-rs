//! Hybrid signing at the metablock level.
//!
//! in-toto's `signatures` is a list, so a single metablock can carry a
//! classical and a post-quantum signature side by side. That gives the same
//! "either algorithm breaking leaves the other binding" property as a composite
//! signature, while old verifiers keep working off the Ed25519 entry.

#![cfg(feature = "mldsa")]

use in_toto::crypto::{KeyType, PrivateKey, SignatureScheme};
use in_toto::models::{LinkMetadataBuilder, Metablock, MetadataWrapper};

const PRIVATE_PEM: &str = include_str!("data/mldsa/mldsa65_private.pem");

fn mldsa_key() -> PrivateKey {
    let der = pem::parse(PRIVATE_PEM).expect("valid pem");
    PrivateKey::from_pkcs8(der.contents(), SignatureScheme::MlDsa65V1)
        .expect("ml-dsa key parses")
}

fn ed25519_key() -> PrivateKey {
    let der = PrivateKey::new(KeyType::Ed25519).expect("keygen works");
    PrivateKey::from_pkcs8(&der, SignatureScheme::Ed25519)
        .expect("ed25519 key parses")
}

fn link() -> MetadataWrapper {
    MetadataWrapper::Link(
        LinkMetadataBuilder::new()
            .name("rebuild".into())
            .build()
            .expect("link builds"),
    )
}

#[test]
fn metablock_signed_with_mldsa_only() {
    let key = mldsa_key();
    let block = Metablock::new(link(), &[&key]).expect("signs");

    assert_eq!(block.signatures.len(), 1);
    block
        .verify(1, [key.public()])
        .expect("ml-dsa signature verifies");
}

#[test]
fn metablock_carries_both_ed25519_and_mldsa() {
    let pq = mldsa_key();
    let classical = ed25519_key();

    let block =
        Metablock::new(link(), &[&classical, &pq]).expect("dual signing works");

    assert_eq!(block.signatures.len(), 2, "expected a hybrid metablock");

    // Either signature alone satisfies a threshold of one...
    block
        .verify(1, [classical.public()])
        .expect("ed25519 half verifies on its own");
    block
        .verify(1, [pq.public()])
        .expect("ml-dsa half verifies on its own");

    // ...and together they satisfy a threshold of two.
    block
        .verify(2, [classical.public(), pq.public()])
        .expect("both signatures verify together");
}

#[test]
fn hybrid_metablock_survives_a_json_roundtrip() {
    let pq = mldsa_key();
    let classical = ed25519_key();
    let block = Metablock::new(link(), &[&classical, &pq]).expect("signs");

    let json = serde_json::to_string(&block).expect("serialises");
    let parsed: Metablock = serde_json::from_str(&json).expect("deserialises");

    parsed
        .verify(2, [classical.public(), pq.public()])
        .expect("signatures survive serialisation");
}
