//! in-toto layout's Inspection

use serde_derive::{Deserialize, Serialize};

use super::{rule::ArtifactRule, step::Command, supply_chain_item::SupplyChainItem};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Inspection {
    #[serde(flatten)]
    supply_chain_item: SupplyChainItem,
    run: Command,
}

impl Inspection {
    pub fn new(name: &str) -> Self {
        Inspection {
            run: Command::default(),
            supply_chain_item: SupplyChainItem::new(name.into()),
        }
    }

    /// Set expected command for this Inspection
    pub fn run(mut self, command: Command) -> Self {
        self.run = command;
        self
    }

    /// Add an expected material artifact rule to this Inspection
    pub fn add_expected_material(mut self, expected_material: ArtifactRule) -> Self {
        self.supply_chain_item
            .add_expected_material(expected_material);
        self
    }

    /// Set expected materials for this Inspection
    pub fn expected_materials(mut self, expected_materials: Vec<ArtifactRule>) -> Self {
        self.supply_chain_item
            .set_expected_materials(expected_materials);
        self
    }

    /// Add an expected product artifact rule to this Inspection
    pub fn add_expected_product(mut self, expected_product: ArtifactRule) -> Self {
        self.supply_chain_item
            .add_expected_product(expected_product);
        self
    }

    /// Set expected products for this Inspection
    pub fn expected_products(mut self, expected_products: Vec<ArtifactRule>) -> Self {
        self.supply_chain_item
            .set_expected_products(expected_products);
        self
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::Inspection;
    use crate::models::rule::test::{generate_materials_rule, generate_products_rule};

    #[test]
    fn serialize_inspection() {
        let json = json!({
            "_name": "test_inspect",
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
            "run" : "ls -al"
        })
        .to_string();
        let inspection = Inspection::new("test_inspect")
            .add_expected_material(generate_materials_rule())
            .add_expected_product(generate_products_rule())
            .run("ls -al".into());

        let json_serialized = serde_json::to_string(&inspection).unwrap();
        assert_eq!(json, json_serialized);
    }

    #[test]
    fn deserialize_inspection() {
        let json = r#"{
            "_name": "test_inspect",
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
            "run" : "ls -al"
        }"#;

        let inspection = Inspection::new("test_inspect")
            .add_expected_material(generate_materials_rule())
            .add_expected_product(generate_products_rule())
            .run("ls -al".into());
        let inspection_parsed: Inspection = serde_json::from_str(json).unwrap();
        assert_eq!(inspection_parsed, inspection);
    }
}
