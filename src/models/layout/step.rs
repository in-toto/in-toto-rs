//! in-toto layout's Step

use std::str::FromStr;

use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::crypto::KeyId;
use crate::{supply_chain_item_derive, Error, Result};

use super::rule::ArtifactRule;
use super::supply_chain_item::SupplyChainItem;

/// Wrapper type for a command in step.
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Deserialize,
)]
pub struct Command(Vec<String>);

impl Command {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[String]> for Command {
    fn as_ref(&self) -> &[String] {
        &self.0
    }
}

impl From<String> for Command {
    fn from(str: String) -> Self {
        let paras: Vec<String> = str
            .split_whitespace()
            .collect::<Vec<&str>>()
            .iter()
            .map(|s| s.to_string())
            .collect();
        Command(paras)
    }
}

impl From<Vec<String>> for Command {
    fn from(strs: Vec<String>) -> Self {
        Command::from(&strs[..])
    }
}

impl From<&[String]> for Command {
    fn from(strs: &[String]) -> Self {
        Command(strs.to_vec())
    }
}

impl From<&str> for Command {
    fn from(str: &str) -> Self {
        let paras: Vec<String> = str
            .split_whitespace()
            .collect::<Vec<&str>>()
            .iter()
            .map(|s| s.to_string())
            .collect();
        Command(paras)
    }
}

impl FromStr for Command {
    type Err = Error;

    /// Parse a Command from a string.
    fn from_str(string: &str) -> Result<Self> {
        let paras: Vec<String> = string
            .split_whitespace()
            .collect::<Vec<&str>>()
            .iter()
            .map(|s| s.to_string())
            .collect();
        Ok(Command(paras))
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

/// Step represents an in-toto step of the supply chain performed by a functionary.
/// During final product verification in-toto looks for corresponding Link
/// metadata, which is used as signed evidence that the step was performed
/// according to the supply chain definition.
/// Materials and products used/produced by the step are constrained by the
/// artifact rules in the step's supply_chain_item's expected_materials and
/// expected_products fields.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Step {
    #[serde(rename = "_type")]
    pub typ: String,
    pub threshold: u32,
    pub name: String,
    pub expected_materials: Vec<ArtifactRule>,
    pub expected_products: Vec<ArtifactRule>,
    #[serde(rename = "pubkeys")]
    pub pub_keys: Vec<KeyId>,
    pub expected_command: Command,
}

impl Step {
    pub fn new(name: &str) -> Self {
        Step {
            pub_keys: Vec::new(),
            expected_command: Command::default(),
            threshold: 0,
            name: name.into(),
            expected_materials: Vec::new(),
            expected_products: Vec::new(),
            typ: "step".into(),
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

    // Derive operations on `materials`/`products` and `name`
    supply_chain_item_derive!();
}

impl SupplyChainItem for Step {
    fn name(&self) -> &str {
        &self.name
    }

    fn expected_materials(&self) -> &Vec<ArtifactRule> {
        &self.expected_materials
    }

    fn expected_products(&self) -> &Vec<ArtifactRule> {
        &self.expected_products
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use serde_json::json;

    use crate::{
        crypto::KeyId,
        models::rule::{Artifact, ArtifactRule},
        Result,
    };

    use super::Step;

    #[test]
    fn serialize_step() -> Result<()> {
        let step = Step::new("package")
            .add_expected_material(ArtifactRule::Match {
                pattern: "foo.py".into(),
                in_src: None,
                with: Artifact::Products,
                in_dst: None,
                from: "write-code".into(),
            })
            .add_expected_product(ArtifactRule::Create("foo.tar.gz".into()))
            .expected_command("tar zcvf foo.tar.gz foo.py".into())
            .add_key(KeyId::from_str(
                "70ca5750c2eda80b18f41f4ec5f92146789b5d68dd09577be422a0159bd13680",
            )?)
            .threshold(1);

        let json_serialize = serde_json::to_value(&step)?;
        let json = json!(
        {
            "_type": "step",
            "name": "package",
            "expected_materials": [
               ["MATCH", "foo.py", "WITH", "PRODUCTS", "FROM", "write-code"]
            ],
            "expected_products": [
               ["CREATE", "foo.tar.gz"]
            ],
            "expected_command": ["tar", "zcvf", "foo.tar.gz", "foo.py"],
            "pubkeys": [
               "70ca5750c2eda80b18f41f4ec5f92146789b5d68dd09577be422a0159bd13680"
            ],
            "threshold": 1
          }
        );
        assert_eq!(
            json, json_serialize,
            "{:#?} != {:#?}",
            json, json_serialize
        );
        Ok(())
    }

    #[test]
    fn deserialize_step() -> Result<()> {
        let json = r#"
        {
            "_type": "step",
            "name": "package",
            "expected_materials": [
               ["MATCH", "foo.py", "WITH", "PRODUCTS", "FROM", "write-code"]
            ],
            "expected_products": [
               ["CREATE", "foo.tar.gz"]
            ],
            "expected_command": ["tar", "zcvf", "foo.tar.gz", "foo.py"],
            "pubkeys": [
               "70ca5750c2eda80b18f41f4ec5f92146789b5d68dd09577be422a0159bd13680"
            ],
            "threshold": 1
          }"#;
        let step_parsed: Step = serde_json::from_str(json)?;
        let step = Step::new("package")
            .add_expected_material(ArtifactRule::Match {
                pattern: "foo.py".into(),
                in_src: None,
                with: Artifact::Products,
                in_dst: None,
                from: "write-code".into(),
            })
            .add_expected_product(ArtifactRule::Create("foo.tar.gz".into()))
            .expected_command("tar zcvf foo.tar.gz foo.py".into())
            .add_key(KeyId::from_str(
                "70ca5750c2eda80b18f41f4ec5f92146789b5d68dd09577be422a0159bd13680",
            )?)
            .threshold(1);
        assert_eq!(step_parsed, step);
        Ok(())
    }
}
