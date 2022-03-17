//! Supporting Functions and Types (VirtualTargetPath)
use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use std::collections::{HashMap};
use std::fmt::Debug;
use std::str;
use std::fs::canonicalize as canonicalize_path;
use std::path::Path;
use serde_derive::Serialize;
use crate::crypto::{HashAlgorithm, HashValue};
use crate::Result;
use crate::error::Error;


/// Description of a target, used in verification.
pub type TargetDescription = HashMap<HashAlgorithm, HashValue>;

/// Wrapper for the Virtual path to a target.
#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize)]
pub struct VirtualTargetPath(String);

impl VirtualTargetPath {
    /// Create a new `VirtualTargetPath` from a `String`.
    ///
    pub fn new(path: String) -> Result<Self> {
        //safe_path(&path)?;
        let cleaned_path = match canonicalize_path(Path::new(path.as_str())) {
            Ok(path_buf) => {
                match path_buf.to_str() {
                   Some(x) => x.to_string(),
                   None => " ".to_string() // TODO
                }
            },
            Err(e) => return Err(Error::from(e))
        };
        Ok(VirtualTargetPath(cleaned_path))
    }

    /// The string value of the path.
    pub fn value(&self) -> &str {
        &self.0
    }
}

impl ToString for VirtualTargetPath {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl<'de> Deserialize<'de> for VirtualTargetPath {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        VirtualTargetPath::new(s).map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}
