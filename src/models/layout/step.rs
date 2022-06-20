//! in-toto layout's Step

use std::str::FromStr;

use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use serde::ser::{Serialize, Serializer};
use serde_derive::{Deserialize, Serialize};

use crate::crypto::KeyId;
use crate::{Error, Result};

/// TODO ArtifactRule
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ArtifactRule {}

/// SupplyChainItem summarizes common fields of the two available supply chain
/// item types in Inspection and Step.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SupplyChainItem {
    name: String,
    expected_materials: Vec<ArtifactRule>,
    expected_products: Vec<ArtifactRule>,
}

impl SupplyChainItem {
    /// Create new `SupplyChainItem`.
    pub fn new(name: String) -> Self {
        SupplyChainItem {
            name,
            expected_materials: Vec::new(),
            expected_products: Vec::new(),
        }
    }

    /// Add an expected material artifact rule to this SupplyChainItem
    pub fn add_expected_material(&mut self, expected_material: ArtifactRule) {
        self.expected_materials.push(expected_material);
    }

    /// Set expected materials for this SupplyChainItem
    pub fn set_expected_materials(&mut self, expected_materials: Vec<ArtifactRule>) {
        self.expected_materials = expected_materials;
    }

    /// Add an expected product artifact rule to this SupplyChainItem
    pub fn add_expected_products(&mut self, expected_product: ArtifactRule) {
        self.expected_products.push(expected_product);
    }

    /// Set expected products for this SupplyChainItem
    pub fn set_expected_products(&mut self, expected_products: Vec<ArtifactRule>) {
        self.expected_products = expected_products;
    }

    /// Artifact name of this SupplyChainItem
    pub fn name(&self) -> &String {
        &self.name
    }

    /// Expected materials of this SupplyChainItem
    pub fn expected_materials(&self) -> &Vec<ArtifactRule> {
        &self.expected_materials
    }

    /// Expected products of this SupplyChainItem
    pub fn expected_products(&self) -> &Vec<ArtifactRule> {
        &self.expected_products
    }
}

/// Wrapper type for a command in step.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Command(String);

impl FromStr for Command {
    type Err = Error;

    /// Parse a Command from a string.
    fn from_str(string: &str) -> Result<Self> {
        Ok(Command(string.to_owned()))
    }
}

impl Serialize for Command {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(ser)
    }
}

impl<'de> Deserialize<'de> for Command {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let string: String = Deserialize::deserialize(de)?;
        Command::from_str(&string).map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

/// Step represents an in-toto step of the supply chain performed by a functionary.
/// During final product verification in-toto looks for corresponding Link
/// metadata, which is used as signed evidence that the step was performed
/// according to the supply chain definition.
/// Materials and products used/produced by the step are constrained by the
/// artifact rules in the step's supply_chain_item's expected_materials and
/// expected_products fields.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Step {
    #[serde(skip)]
    typ: String,
    pub_keys: Vec<KeyId>,
    expected_command: Vec<Command>,
    threshold: u32,
    #[serde(flatten)]
    supply_chain_item: SupplyChainItem,
}

impl Step {
    pub fn new(name: &str) -> Self {
        Step {
            typ: "step".into(),
            pub_keys: Vec::new(),
            expected_command: Vec::new(),
            threshold: 0,
            supply_chain_item: SupplyChainItem::new(name.into()),
        }
    }

    /// Add a pub key for this Step
    pub fn add_key(mut self, key: KeyId) -> Self {
        self.pub_keys.push(key);
        self
    }

    /// Add a expected command for this Step
    pub fn add_expected_command(mut self, command: Command) -> Self {
        self.expected_command.push(command);
        self
    }

    /// Set threshold for this Step
    pub fn threshold(mut self, threshold: u32) -> Self {
        self.threshold = threshold;
        self
    }

    /// Add an expected material artifact rule to this Step
    pub fn add_expected_material(mut self, expected_material: ArtifactRule) -> Self {
        self.supply_chain_item
            .add_expected_material(expected_material);
        self
    }

    /// Set expected materials for this Step
    pub fn expected_materials(mut self, expected_materials: Vec<ArtifactRule>) -> Self {
        self.supply_chain_item
            .set_expected_materials(expected_materials);
        self
    }

    /// Add an expected product artifact rule to this Step
    pub fn add_expected_products(mut self, expected_product: ArtifactRule) -> Self {
        self.supply_chain_item
            .add_expected_products(expected_product);
        self
    }

    /// Set expected products for this Step
    pub fn expected_products(mut self, expected_products: Vec<ArtifactRule>) -> Self {
        self.supply_chain_item
            .set_expected_products(expected_products);
        self
    }
}
