//！ SupplyChainItem summarizes common fields of the two available supply chain
//！ item types in Inspection and Step.

use serde_derive::{Deserialize, Serialize};

use super::rule::ArtifactRule;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SupplyChainItem {
    #[serde(rename = "_name")]
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