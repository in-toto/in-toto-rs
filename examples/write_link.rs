use in_toto::metadata::{LinkMetadataBuilder, VirtualTargetPath};
use in_toto::crypto::{PrivateKey, KeyType, SignatureScheme};
use in_toto::interchange::Json;
use serde_json;

fn main() {
    // Generate a new Ed25519 signing key
    let key = PrivateKey::new(KeyType::Ed25519).unwrap();
    println!("Generated keypair: {:?}", key);
    let privkey  = PrivateKey::from_pkcs8(&key, SignatureScheme::Ed25519).unwrap();

    let link = LinkMetadataBuilder::new()
                .name(String::from("test"))
                .add_material(VirtualTargetPath::new("LICENSE".to_string()).unwrap())
                .add_product(VirtualTargetPath::new("Makefile".to_string()).unwrap())
                .signed::<Json>(&privkey)
                .unwrap();

    let json = serde_json::to_value(&link).unwrap();

    println!("Generated link: {}", json)
}
