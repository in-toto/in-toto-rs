//！ SupplyChainItem summarizes common fields of the two available supply chain
//！ item types in Inspection and Step.

use super::rule::ArtifactRule;

pub trait SupplyChainItem {
    /// Get the name of this item
    fn name(&self) -> &str;

    /// Get the expected material
    fn expected_materials(&self) -> &Vec<ArtifactRule>;

    /// Get the expected products
    fn expected_products(&self) -> &Vec<ArtifactRule>;
}

#[macro_export]
macro_rules! supply_chain_item_derive {
    () => {
        /// Add an expected material artifact rule to this Step
        pub fn add_expected_material(mut self, expected_material: ArtifactRule) -> Self {
            self.expected_materials.push(expected_material);
            self
        }

        /// Set expected materials for this Step
        pub fn expected_materials(mut self, expected_materials: Vec<ArtifactRule>) -> Self {
            self.expected_materials = expected_materials;
            self
        }

        /// Add an expected product artifact rule to this Step
        pub fn add_expected_product(mut self, expected_product: ArtifactRule) -> Self {
            self.expected_products.push(expected_product);
            self
        }

        /// Set expected products for this Step
        pub fn expected_products(mut self, expected_products: Vec<ArtifactRule>) -> Self {
            self.expected_products = expected_products;
            self
        }
    };
}
