//! in-toto layout's Inspection

use serde_derive::{Deserialize, Serialize};

use crate::supply_chain_item_derive;

use super::{
    rule::ArtifactRule, step::Command, supply_chain_item::SupplyChainItem,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Inspection {
    #[serde(rename = "_type")]
    pub typ: String,
    #[serde(rename = "name")]
    pub name: String,
    pub expected_materials: Vec<ArtifactRule>,
    pub expected_products: Vec<ArtifactRule>,
    pub run: Command,
}

impl Inspection {
    pub fn new(name: &str) -> Self {
        Inspection {
            run: Command::default(),
            name: name.into(),
            expected_materials: Vec::new(),
            expected_products: Vec::new(),
            typ: "inspection".into(),
        }
    }

    /// Set expected command for this Inspection
    pub fn run(mut self, command: Command) -> Self {
        self.run = command;
        self
    }

    // Derive operations on `materials`/`products` and `name`
    supply_chain_item_derive!();
}

impl SupplyChainItem for Inspection {
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
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    use super::Inspection;
    use crate::models::rule::test::{
        generate_materials_rule, generate_products_rule,
    };

    #[test]
    fn serialize_inspection() {
        let json = json!({
            "_type": "inspection",
            "name": "test_inspect",
            "expected_materials" : [
                [
                    "MATCH",
                    "pattern/",
                    "IN",
                    "src",
                    "WITH",
                    "MATERIALS",
                    "IN",
                    "dst",
                    "FROM",
                    "test_step"
                ]
            ],
            "expected_products" : [
                [
                    "MATCH",
                    "pattern/",
                    "IN",
                    "src",
                    "WITH",
                    "PRODUCTS",
                    "IN",
                    "dst",
                    "FROM",
                    "test_step"
                ]
            ],
            "run" : ["ls", "-al"]
        });
        let inspection = Inspection::new("test_inspect")
            .add_expected_material(generate_materials_rule())
            .add_expected_product(generate_products_rule())
            .run("ls -al".into());

        let json_serialized = serde_json::to_value(&inspection).unwrap();
        assert_json_eq!(json, json_serialized);
    }

    #[test]
    fn deserialize_inspection() {
        let json = r#"{
            "_type": "inspection",
            "name": "test_inspect",
            "expected_materials" : [
                [
                    "MATCH", 
                    "pattern/", 
                    "IN", 
                    "src", 
                    "WITH", 
                    "MATERIALS", 
                    "IN", 
                    "dst", 
                    "FROM", 
                    "test_step"
                ] 
            ],
            "expected_products" : [
                [
                    "MATCH", 
                    "pattern/", 
                    "IN", 
                    "src", 
                    "WITH", 
                    "PRODUCTS", 
                    "IN", 
                    "dst", 
                    "FROM", 
                    "test_step"
                ] 
            ],
            "run" : ["ls", "-al"]
        }"#;

        let inspection = Inspection::new("test_inspect")
            .add_expected_material(generate_materials_rule())
            .add_expected_product(generate_products_rule())
            .run("ls -al".into());
        let inspection_parsed: Inspection = serde_json::from_str(json).unwrap();
        assert_eq!(inspection_parsed, inspection);
    }
}
