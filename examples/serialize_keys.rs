use in_toto::crypto::{KeyType, PrivateKey, SignatureScheme};
use std::fs;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::os::unix::fs::OpenOptionsExt;

fn main() {
    // Generate a new Ed25519 signing key
    let key = PrivateKey::new(KeyType::Ed25519).unwrap();
    let mut privkey = PrivateKey::from_pkcs8(&key, SignatureScheme::Ed25519).unwrap();
    println!("Generated keypair {:?}", &privkey.public());

    let mut target = OpenOptions::new()
        .mode(0o640)
        .write(true)
        .create(true)
        .open("test-key")
        .unwrap();
    target.write_all(&key).unwrap();

    let loaded_key = fs::read("test-key").unwrap();
    privkey = PrivateKey::from_pkcs8(&loaded_key, SignatureScheme::Ed25519).unwrap();

    println!("loaded keypair: {:?}", &privkey.public())
}
