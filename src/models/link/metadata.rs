//! in-toto link metadata.

use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use serde::ser::{Error as SerializeError, Serialize, Serializer};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::fs::File;
use std::io::BufReader;

use crate::crypto::{self, PrivateKey};
use crate::interchange::{DataInterchange, Json};
use crate::Result;

use crate::models::step::Command;
use crate::models::{
    Link, Metablock, Metadata, MetadataType, MetadataWrapper, TargetDescription, VirtualTargetPath,
};

use super::byproducts::ByProducts;

/// Helper to construct `LinkMetadata`.
pub struct LinkMetadataBuilder {
    name: String,
    materials: BTreeMap<VirtualTargetPath, TargetDescription>,
    products: BTreeMap<VirtualTargetPath, TargetDescription>,
    env: Option<BTreeMap<String, String>>,
    byproducts: ByProducts,
    command: Command,
}

impl Default for LinkMetadataBuilder {
    fn default() -> Self {
        LinkMetadataBuilder::new()
    }
}

impl LinkMetadataBuilder {
    pub fn new() -> Self {
        LinkMetadataBuilder {
            name: String::new(),
            materials: BTreeMap::new(),
            products: BTreeMap::new(),
            env: None,
            byproducts: ByProducts::new(),
            command: Command::default(),
        }
    }

    /// Set the name number for this link
    pub fn name(mut self, name: String) -> Self {
        self.name = name;
        self
    }

    /// Set the materials for this metadata
    pub fn materials(mut self, materials: BTreeMap<VirtualTargetPath, TargetDescription>) -> Self {
        self.materials = materials;
        self
    }

    /// Set the products for this metadata
    pub fn products(mut self, products: BTreeMap<VirtualTargetPath, TargetDescription>) -> Self {
        self.products = products;
        self
    }

    pub fn add_material(mut self, material_path: VirtualTargetPath) -> Self {
        let file = File::open(material_path.to_string()).unwrap();
        let mut reader = BufReader::new(file);
        let (_length, hashes) =
            crypto::calculate_hashes(&mut reader, &[crypto::HashAlgorithm::Sha256]).unwrap();
        self.materials.insert(material_path, hashes);
        self
    }

    pub fn add_product(mut self, material_path: VirtualTargetPath) -> Self {
        let file = File::open(material_path.to_string()).unwrap();
        let mut reader = BufReader::new(file);
        let (_length, hashes) =
            crypto::calculate_hashes(&mut reader, &[crypto::HashAlgorithm::Sha256]).unwrap();
        self.products.insert(material_path, hashes);
        self
    }

    /// Set the products for this metadata
    pub fn env(mut self, env: Option<BTreeMap<String, String>>) -> Self {
        self.env = env;
        self
    }

    /// Set the products for this metadata
    pub fn byproducts(mut self, byproducts: ByProducts) -> Self {
        self.byproducts = byproducts;
        self
    }

    /// Set the command for this metadata
    pub fn command(mut self, command: Command) -> Self {
        self.command = command;
        self
    }

    pub fn build(self) -> Result<LinkMetadata> {
        LinkMetadata::new(
            self.name,
            self.materials,
            self.products,
            self.env,
            self.byproducts,
            self.command,
        )
    }

    /// Construct a new `Metablock<D, LinkMetadata>`.
    pub fn signed<D>(self, private_key: &PrivateKey) -> Result<Metablock>
    where
        D: DataInterchange,
    {
        Metablock::new(Box::new(self.build()?).into_enum(), &[private_key])
    }

    /// Construct a new `Metablock<D, LinkMetadata>`.
    pub fn unsigned<D>(self) -> Result<Metablock>
    where
        D: DataInterchange,
    {
        Metablock::new(Box::new(self.build()?).into_enum(), &[])
    }
}

/// link metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkMetadata {
    name: String,
    materials: BTreeMap<VirtualTargetPath, TargetDescription>,
    products: BTreeMap<VirtualTargetPath, TargetDescription>,
    env: Option<BTreeMap<String, String>>,
    byproducts: ByProducts,
    command: Command,
}

impl LinkMetadata {
    /// Create new `LinkMetadata`.
    pub fn new(
        name: String,
        materials: BTreeMap<VirtualTargetPath, TargetDescription>,
        products: BTreeMap<VirtualTargetPath, TargetDescription>,
        env: Option<BTreeMap<String, String>>,
        byproducts: ByProducts,
        command: Command,
    ) -> Result<Self> {
        Ok(LinkMetadata {
            name,
            materials,
            products,
            env,
            byproducts,
            command,
        })
    }

    // The step this link is associated to
    pub fn name(&self) -> &String {
        &self.name
    }

    // The materials used as inputs
    pub fn materials(&self) -> &BTreeMap<VirtualTargetPath, TargetDescription> {
        &self.materials
    }

    // The products used as inputs
    pub fn products(&self) -> &BTreeMap<VirtualTargetPath, TargetDescription> {
        &self.products
    }

    // The Environment where things were built
    pub fn env(&self) -> &Option<BTreeMap<String, String>> {
        &self.env
    }

    // The Environment where things were built
    pub fn byproducts(&self) -> &ByProducts {
        &self.byproducts
    }

    // The command of the link
    pub fn command(&self) -> &Command {
        &self.command
    }
}

impl Metadata for LinkMetadata {
    fn typ(&self) -> MetadataType {
        MetadataType::Link
    }

    fn into_enum(self: Box<Self>) -> MetadataWrapper {
        MetadataWrapper::Link(*self)
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        Json::canonicalize(&Json::serialize(self)?)
    }
}

impl Serialize for LinkMetadata {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Link::from(self)
            .map_err(|e| SerializeError::custom(format!("{:?}", e)))?
            .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for LinkMetadata {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: Link = Deserialize::deserialize(de)?;
        intermediate
            .try_into()
            .map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::models::{
        byproducts::ByProducts, step::Command, LinkMetadata, LinkMetadataBuilder, VirtualTargetPath,
    };

    #[test]
    fn serialize_linkmetadata() {
        let link_metadata = LinkMetadataBuilder::new()
            .name("".into())
            .add_product(VirtualTargetPath::new("tests/test_link/foo.tar.gz".into()).unwrap())
            .byproducts(
                ByProducts::new()
                    .set_return_value(0)
                    .set_stderr("a foo.py\n".into())
                    .set_stdout("".into()),
            )
            .command(Command::from("tar zcvf foo.tar.gz foo.py"))
            .build()
            .unwrap();

        let serialized_linkmetadata = serde_json::to_value(link_metadata).unwrap();
        let json = json!({
            "_type": "link",
            "name": "",
            "materials": {},
            "products": {
                "tests/test_link/foo.tar.gz": {
                    "sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e6936c1e5aabb7c98514f355"
                }
            },
            "byproducts": {
                "return-value": 0,
                "stderr": "a foo.py\n",
                "stdout": ""
            },
            "command": "tar zcvf foo.tar.gz foo.py",
            "environment": null
        });
        assert_eq!(json, serialized_linkmetadata);
    }

    #[test]
    fn deserialize_linkmetadata() {
        let json = r#"{
            "_type": "link",
            "name": "",
            "materials": {},
            "products": {
                "tests/test_link/foo.tar.gz": {
                    "sha256": "52947cb78b91ad01fe81cd6aef42d1f6817e92b9e6936c1e5aabb7c98514f355"
                }
            },
            "byproducts": {
                "return-value": 0,
                "stderr": "a foo.py\n",
                "stdout": ""
            },
            "command": "tar zcvf foo.tar.gz foo.py",
            "environment": null
        }"#;

        let link_metadata = LinkMetadataBuilder::new()
            .name("".into())
            .add_product(VirtualTargetPath::new("tests/test_link/foo.tar.gz".into()).unwrap())
            .byproducts(
                ByProducts::new()
                    .set_return_value(0)
                    .set_stderr("a foo.py\n".into())
                    .set_stdout("".into()),
            )
            .command(Command::from("tar zcvf foo.tar.gz foo.py"))
            .build()
            .unwrap();

        let deserialized_link_metadata: LinkMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(link_metadata, deserialized_link_metadata);
    }
}
