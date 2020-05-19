use in_toto::crypto::{PrivateKey, KeyType, SignatureScheme};
use std::fs;
use std::path::Path;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::io::prelude::*;

fn main() {
    // Generate a new Ed25519 signing key
    let key = PrivateKey::new(KeyType::Ed25519).unwrap();
    let mut privkey = PrivateKey::from_pkcs8(&key, SignatureScheme::Ed25519).unwrap();
    println!("Generated keypair {:?}", &privkey.public());

    let mut target = OpenOptions::new()
           .mode(0o640)
           .write(true)
           .create(true)
           .open("test-key").unwrap();
    target.write_all(&key).unwrap();

    let loaded_key = fs::read("test-key").unwrap();
    privkey = PrivateKey::from_pkcs8(&loaded_key, SignatureScheme::Ed25519).unwrap();

    println!("loaded keypair: {:?}", &privkey.public())
}
