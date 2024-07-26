//! in-toto link's byproducts
//!
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
/// //  .set_other_fields(other_byproducts);
/// ```
///
/// Also, can directly set a whole BTree<String, String> as other_fields
///
/// ```
/// use std::collections::BTreeMap;
/// use in_toto::models::byproducts::ByProducts;
/// let mut other_byproducts: BTreeMap<String, String> = BTreeMap::new();
/// other_byproducts.insert("key".into(), "value".into());
///
/// let byproducts = ByProducts::new()
///     .set_return_value(0)
///     .set_stderr("".into())
///     .set_stdout("".into())
///     .set_other_fields(other_byproducts);
/// ```
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ByProducts {
    #[serde(rename = "return-value", skip_serializing_if = "Option::is_none")]
    return_value: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stderr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stdout: Option<String>,
    #[serde(flatten)]
    other_fields: BTreeMap<String, String>,
}

impl ByProducts {
    pub fn new() -> Self {
        ByProducts {
            return_value: None,
            stderr: None,
            stdout: None,
            other_fields: BTreeMap::new(),
        }
    }

    /// Set return-value
    pub fn set_return_value(mut self, return_value: i32) -> Self {
        self.return_value = Some(return_value);
        self
    }

    /// Set stderr
    pub fn set_stderr(mut self, stderr: String) -> Self {
        self.stderr = Some(stderr);
        self
    }

    /// Set stdout
    pub fn set_stdout(mut self, stdout: String) -> Self {
        self.stdout = Some(stdout);
        self
    }

    /// Set other fields.
    /// Warning: This operation will overwrite all the present other-field
    /// set by `set_other_field` or `set_other_fields` before.
    pub fn set_other_fields(
        mut self,
        other_fields: BTreeMap<String, String>,
    ) -> Self {
        self.other_fields = other_fields;
        self
    }

    /// Insert another field
    pub fn set_other_field(mut self, key: String, value: String) -> Self {
        self.other_fields.insert(key, value);
        self
    }

    /// Get return-value
    pub fn return_value(&self) -> Option<i32> {
        self.return_value
    }

    /// Get stderr
    pub fn stderr(&self) -> &Option<String> {
        &self.stderr
    }

    /// Get stdout
    pub fn stdout(&self) -> &Option<String> {
        &self.stdout
    }

    /// Get other fields
    pub fn other_fields(&self) -> &BTreeMap<String, String> {
        &self.other_fields
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::ByProducts;

    #[test]
    fn serialize_byproducts_other_field() {
        let byproducts = ByProducts::new()
            .set_return_value(0)
            .set_stderr("a foo.py\n".into())
            .set_stdout("".into())
            .set_other_field("key1".into(), "value1".into())
            .set_other_field("key2".into(), "value2".into());

        let serialized_byproducts = serde_json::to_value(byproducts).unwrap();
        let json = json!({
            "return-value": 0,
            "stderr": "a foo.py\n",
            "stdout": "",
            "key1": "value1",
            "key2": "value2"
        });
        assert_eq!(json, serialized_byproducts);
    }

    #[test]
    fn serialize_byproducts_other_fields() {
        let mut other_fields = BTreeMap::new();
        other_fields.insert("key1".into(), "value1".into());
        other_fields.insert("key2".into(), "value2".into());

        let byproducts = ByProducts::new()
            .set_return_value(0)
            .set_stderr("a foo.py\n".into())
            .set_stdout("".into())
            .set_other_fields(other_fields);

        let serialized_byproducts = serde_json::to_value(byproducts).unwrap();
        let json = json!({
            "return-value": 0,
            "stderr": "a foo.py\n",
            "stdout": "",
            "key1": "value1",
            "key2": "value2"
        });
        assert_eq!(json, serialized_byproducts);
    }

    #[test]
    fn deserialize_byproducts_other_field() {
        let json = r#"{
            "return-value": 0,
            "stderr": "a foo.py\n",
            "stdout": "",
            "key1": "value1",
            "key2": "value2"
        }"#;

        let byproducts = ByProducts::new()
            .set_return_value(0)
            .set_stderr("a foo.py\n".into())
            .set_stdout("".into())
            .set_other_field("key1".into(), "value1".into())
            .set_other_field("key2".into(), "value2".into());

        let deserialized_byproducts: ByProducts =
            serde_json::from_str(json).unwrap();
        assert_eq!(byproducts, deserialized_byproducts);
    }

    #[test]
    fn deserialize_byproducts_other_fields() {
        let json = r#"{
            "return-value": 0,
            "stderr": "a foo.py\n",
            "stdout": "",
            "key1": "value1",
            "key2": "value2"
        }"#;

        let mut other_fields = BTreeMap::new();
        other_fields.insert("key1".into(), "value1".into());
        other_fields.insert("key2".into(), "value2".into());

        let byproducts = ByProducts::new()
            .set_return_value(0)
            .set_stderr("a foo.py\n".into())
            .set_stdout("".into())
            .set_other_fields(other_fields);

        let deserialized_byproducts: ByProducts =
            serde_json::from_str(json).unwrap();
        assert_eq!(byproducts, deserialized_byproducts);
    }
}
