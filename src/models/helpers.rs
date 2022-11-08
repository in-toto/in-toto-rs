//! Supporting Functions and Types (VirtualTargetPath)
use std::collections::HashMap;
use std::fmt::Debug;
use std::str;

use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use serde_derive::Serialize;

use crate::crypto::{HashAlgorithm, HashValue};
use crate::{Error, Result};

/// Description of a target, used in verification.
pub type TargetDescription = HashMap<HashAlgorithm, HashValue>;

/// Wrapper for the Virtual path to a target.
#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize)]
pub struct VirtualTargetPath(String);

impl VirtualTargetPath {
    /// Create a new `VirtualTargetPath` from a `String`.
    ///
    pub fn new(path: String) -> Result<Self> {
        Ok(VirtualTargetPath(path))
    }

    /// The string value of the path.
    pub fn value(&self) -> &str {
        &self.0
    }

    /// Judge if this [`VirtualTargetPath`] matches the given pattern
    pub(crate) fn matches(&self, pattern: &str) -> Result<bool> {
        let matcher = glob::Pattern::new(pattern).map_err(|e| {
            Error::IllegalArgument(format!("Pattern matcher creation failed: {}", e))
        })?;
        Ok(matcher.matches(self.value()))
    }
}

impl ToString for VirtualTargetPath {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl From<&str> for VirtualTargetPath {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for VirtualTargetPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for VirtualTargetPath {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        VirtualTargetPath::new(s).map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

/// Trait for return Result From + Into
pub(crate) trait Convert<T> {
    fn try_from(target: T) -> Result<Self>
    where
        Self: Sized;
    fn try_into(self) -> Result<T>;
}

#[cfg(test)]
mod tests {
    use crate::models::VirtualTargetPath;

    #[test]
    fn serialize_virtual_target_path() {
        let path = VirtualTargetPath::from("foo.py");
        let serialized = serde_json::to_string(&path).expect("serialize failed");
        let expected = "\"foo.py\"";
        assert!(serialized == expected);
    }

    #[test]
    fn deserialize_virtual_target_path() {
        let path = VirtualTargetPath::from("foo.py");
        let deserialized: VirtualTargetPath =
            serde_json::from_str("\"foo.py\"").expect("serialize failed");
        assert!(path == deserialized);
    }
}
