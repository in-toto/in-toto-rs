//! in-toto layout's Step

use std::str::FromStr;

use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use serde::ser::{Serialize, Serializer};
use serde_derive::{Deserialize, Serialize};

use crate::crypto::KeyId;
use crate::{Error, Result};

use super::rule::ArtifactRule;
use super::supply_chain_item::SupplyChainItem;

/// Wrapper type for a command in step.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Command(String);

impl From<String> for Command {
    fn from(str: String) -> Self {
        Command(str)
    }
}

impl From<&str> for Command {
    fn from(str: &str) -> Self {
        Command(str.to_string())
    }
}

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
    #[serde(skip, default = "default_step")]
    typ: String,
    threshold: u32,
    #[serde(flatten)]
    supply_chain_item: SupplyChainItem,
    #[serde(rename = "pubkeys")]
    pub_keys: Vec<KeyId>,
    expected_command: Command,
}

fn default_step() -> String {
    "step".to_string()
}

impl Step {
    pub fn new(name: &str) -> Self {
        Step {
            typ: "step".into(),
            pub_keys: Vec::new(),
            expected_command: Command::default(),
            threshold: 0,
            supply_chain_item: SupplyChainItem::new(name.into()),
        }
    }

    /// Add a pub key for this Step
    pub fn add_key(mut self, key: KeyId) -> Self {
        self.pub_keys.push(key);
        self
    }

    /// Set expected command for this Step
    pub fn expected_command(mut self, command: Command) -> Self {
        self.expected_command = command;
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

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use serde_json::json;

    use crate::{crypto::KeyId, models::rule::ArtifactRuleBuilder, Result};

    use super::Step;

    #[test]
    fn serialize_step() -> Result<()> {
        let step = Step::new("package")
            .add_expected_material(
                ArtifactRuleBuilder::new()
                    .set_type("MATCH")
                    .pattern("foo.py")
                    .products()
                    .step("write-code")
                    .build()?,
            )
            .add_expected_products(
                ArtifactRuleBuilder::new()
                    .set_type("CREATE")
                    .pattern("foo.tar.gz")
                    .build()?,
            )
            .expected_command("tar zcvf foo.tar.gz foo.py".into())
            .add_key(KeyId::from_str(
                "70ca5750c2eda80b18f41f4ec5f92146789b5d68dd09577be422a0159bd13680",
            )?)
            .threshold(1);

        let json_serialize = serde_json::to_value(&step)?;
        let json = json!(
        {
            "_name": "package",
            "expected_materials": [
               ["MATCH", "foo.py", "WITH", "PRODUCTS", "FROM", "write-code"]
            ],
            "expected_products": [
               ["CREATE", "foo.tar.gz"]
            ],
            "expected_command": "tar zcvf foo.tar.gz foo.py",
            "pubkeys": [
               "70ca5750c2eda80b18f41f4ec5f92146789b5d68dd09577be422a0159bd13680"
            ],
            "threshold": 1
          }
        );
        assert_eq!(json, json_serialize, "{:#?} != {:#?}", json, json_serialize);
        Ok(())
    }

    #[test]
    fn deserialize_step() -> Result<()> {
        let json = r#"
        {
            "_name": "package",
            "expected_materials": [
               ["MATCH", "foo.py", "WITH", "PRODUCTS", "FROM", "write-code"]
            ],
            "expected_products": [
               ["CREATE", "foo.tar.gz"]
            ],
            "expected_command": "tar zcvf foo.tar.gz foo.py",
            "pubkeys": [
               "70ca5750c2eda80b18f41f4ec5f92146789b5d68dd09577be422a0159bd13680"
            ],
            "threshold": 1
          }"#;
        let step_parsed: Step = serde_json::from_str(json)?;
        let step = Step::new("package")
            .add_expected_material(
                ArtifactRuleBuilder::new()
                    .set_type("MATCH")
                    .pattern("foo.py")
                    .products()
                    .step("write-code")
                    .build()?,
            )
            .add_expected_products(
                ArtifactRuleBuilder::new()
                    .set_type("CREATE")
                    .pattern("foo.tar.gz")
                    .build()?,
            )
            .expected_command("tar zcvf foo.tar.gz foo.py".into())
            .add_key(KeyId::from_str(
                "70ca5750c2eda80b18f41f4ec5f92146789b5d68dd09577be422a0159bd13680",
            )?)
            .threshold(1);
        assert_eq!(step_parsed, step);
        Ok(())
    }
}
