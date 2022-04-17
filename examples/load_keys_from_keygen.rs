use std::fs;

use data_encoding::HEXLOWER;
use serde_json::Value;

use in_toto::crypto::PrivateKey;

fn main() {
    // Load a Ed25519 signing key
    let json_key_data = fs::read_to_string("examples/keygen_example/ed25519").unwrap();
    let data: Value = serde_json::from_str(&json_key_data).unwrap();

    let private_key_raw = data["keyval"]["private"].as_str().unwrap().as_bytes();
    let public_key_raw = data["keyval"]["public"].as_str().unwrap().as_bytes();

    let mut private_key = HEXLOWER.decode(private_key_raw).unwrap();
    let public_key = HEXLOWER.decode(public_key_raw).unwrap();

    private_key.extend(public_key);

    let privkey = PrivateKey::from_ed25519(&private_key).unwrap();

    println!("loaded keypair: {:?}", &privkey.public())
}
