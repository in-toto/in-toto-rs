//! in-toto link's byproducts
//!
use std::collections::BTreeMap;

use serde_derive::{Deserialize, Serialize};

/// byproducts of a link file
/// # Example
/// ```
/// use in_toto::models::byproducts::ByProducts;
/// // let other_byproducts: BTreeMap<String, String> = BTreeMap::new();
/// // ...
/// // insert some other byproducts to other_byproducts
/// let byproducts = ByProducts::new()
///     .set_return_value(0)
///     .set_stderr("".into())
///     .set_stdout("".into());
/// //  .set_other_set_byproducts(other_byproducts);
/// ```
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct ByProducts {
    #[serde(rename = "return-value")]
    return_value: i32,
    stderr: String,
    stdout: String,
    #[serde(flatten)]
    _byproducts: BTreeMap<String, String>,
}

impl ByProducts {
    pub fn new() -> Self {
        ByProducts {
            return_value: 0,
            stderr: "".into(),
            stdout: "".into(),
            _byproducts: BTreeMap::new(),
        }
    }

    /// Set return-value
    pub fn set_return_value(mut self, return_value: i32) -> Self {
        self.return_value = return_value;
        self
    }

    /// Set stderr
    pub fn set_stderr(mut self, stderr: String) -> Self {
        self.stderr = stderr;
        self
    }

    /// Set stdout
    pub fn set_stdout(mut self, stdout: String) -> Self {
        self.stdout = stdout;
        self
    }

    /// Set byproducts
    pub fn set_other_set_byproducts(mut self, byproducts: BTreeMap<String, String>) -> Self {
        self._byproducts = byproducts;
        self
    }

    /// Get return-value
    pub fn return_value(&self) -> i32 {
        self.return_value
    }

    /// Get stderr
    pub fn stderr(&self) -> &String {
        &self.stderr
    }

    /// Get stdout
    pub fn stdout(&self) -> &String {
        &self.stdout
    }

    /// Get byproducts
    pub fn other_byproducts(&self) -> &BTreeMap<String, String> {
        &self._byproducts
    }
}
