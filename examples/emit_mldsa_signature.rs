//! Emit an ML-DSA signature as JSON on stdout, for cross-checking against
//! securesystemslib.
//!
//! ```sh
//! cargo run --example emit_mldsa_signature --features mldsa \
//!   | python tests/data/mldsa/verify_rust_signature.py
//! ```

#[cfg(not(feature = "mldsa"))]
fn main() {
    eprintln!("rebuild with --features mldsa");
    std::process::exit(1);
}

#[cfg(feature = "mldsa")]
fn main() {
    use in_toto::crypto::{PrivateKey, SignatureScheme};

    const PRIVATE_PEM: &str =
        include_str!("../tests/data/mldsa/mldsa65_private.pem");
    const PUBLIC_PEM: &str =
        include_str!("../tests/data/mldsa/mldsa65_public.pem");

    let msg = b"signed by in-toto-rs, verified by securesystemslib";

    let der = pem::parse(PRIVATE_PEM).expect("private key is valid pem");
    let key =
        PrivateKey::from_pkcs8(der.contents(), SignatureScheme::MlDsa65V1)
            .expect("key parses");
    let sig = key.sign(msg).expect("signing works");

    let out = serde_json::json!({
        "keytype": "ml-dsa",
        "scheme": "ml-dsa-65/1",
        "keyid": key.key_id(),
        "public_pem": PUBLIC_PEM,
        "msg_utf8": String::from_utf8_lossy(msg),
        "signature_hex": data_encoding::HEXLOWER.encode(sig.value().as_bytes()),
    });

    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
