//! Supporting Functions and Types (VirtualTargetPath, safe_path)
use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::str;

use serde_derive::Serialize;

use crate::crypto::{HashAlgorithm, HashValue};
use crate::Result;

use crate::error::Error;

#[rustfmt::skip]
static PATH_ILLEGAL_COMPONENTS: &[&str] = &[
    ".", // current dir
    "..", // parent dir
         // TODO ? "0", // may translate to nul in windows
];

#[rustfmt::skip]
static PATH_ILLEGAL_COMPONENTS_CASE_INSENSITIVE: &[&str] = &[
    // DOS device files
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    "KEYBD$",
    "CLOCK$",
    "SCREEN$",
    "$IDLE$",
    "CONFIG$",
];

#[rustfmt::skip]
static PATH_ILLEGAL_STRINGS: &[&str] = &[
    ":", // for *nix compatibility
    "\\", // for windows compatibility
    "<",
    ">",
    "\"",
    "|",
    "?",
    "*",
    // control characters, all illegal in FAT
    "\u{000}",
    "\u{001}",
    "\u{002}",
    "\u{003}",
    "\u{004}",
    "\u{005}",
    "\u{006}",
    "\u{007}",
    "\u{008}",
    "\u{009}",
    "\u{00a}",
    "\u{00b}",
    "\u{00c}",
    "\u{00d}",
    "\u{00e}",
    "\u{00f}",
    "\u{010}",
    "\u{011}",
    "\u{012}",
    "\u{013}",
    "\u{014}",
    "\u{015}",
    "\u{016}",
    "\u{017}",
    "\u{018}",
    "\u{019}",
    "\u{01a}",
    "\u{01b}",
    "\u{01c}",
    "\u{01d}",
    "\u{01e}",
    "\u{01f}",
    "\u{07f}",
];

pub fn safe_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(Error::IllegalArgument("Path cannot be empty".into()));
    }

    for bad_str in PATH_ILLEGAL_STRINGS {
        if path.contains(bad_str) {
            return Err(Error::IllegalArgument(format!(
                "Path cannot contain {:?}",
                bad_str
            )));
        }
    }

    for component in path.split('/') {
        for bad_str in PATH_ILLEGAL_COMPONENTS {
            if component == *bad_str {
                return Err(Error::IllegalArgument(format!(
                    "Path cannot have component {:?}",
                    component
                )));
            }
        }

        let component_lower = component.to_lowercase();
        for bad_str in PATH_ILLEGAL_COMPONENTS_CASE_INSENSITIVE {
            if component_lower.as_str() == *bad_str {
                return Err(Error::IllegalArgument(format!(
                    "Path cannot have component {:?}",
                    component
                )));
            }
        }
    }

    Ok(())
}

/// Description of a target, used in verification.
pub type TargetDescription = HashMap<HashAlgorithm, HashValue>;

/// Wrapper for the Virtual path to a target.
#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize)]
pub struct VirtualTargetPath(String);

impl VirtualTargetPath {
    /// Create a new `VirtualTargetPath` from a `String`.
    ///
    /// ```
    /// # use in_toto::models::{VirtualTargetPath};
    /// assert!(VirtualTargetPath::new("foo".into()).is_ok());
    /// assert!(VirtualTargetPath::new("../foo".into()).is_err());
    /// assert!(VirtualTargetPath::new("foo/..".into()).is_err());
    /// assert!(VirtualTargetPath::new("foo/../bar".into()).is_err());
    /// assert!(VirtualTargetPath::new("..foo".into()).is_ok());
    /// assert!(VirtualTargetPath::new("foo/..bar".into()).is_ok());
    /// assert!(VirtualTargetPath::new("foo/bar..".into()).is_ok());
    /// ```
    pub fn new(path: String) -> Result<Self> {
        safe_path(&path)?;
        Ok(VirtualTargetPath(path))
    }

    /// Split `VirtualTargetPath` into components that can be joined to create URL paths, Unix
    /// paths, or Windows paths.
    ///
    /// ```
    /// # use in_toto::models::{VirtualTargetPath};
    /// let path = VirtualTargetPath::new("foo/bar".into()).unwrap();
    /// assert_eq!(path.components(), ["foo".to_string(), "bar".to_string()]);
    /// ```
    pub fn components(&self) -> Vec<String> {
        self.0.split('/').map(|s| s.to_string()).collect()
    }

    /// Return whether this path is the child of another path.
    ///
    /// ```
    /// # use in_toto::models::{VirtualTargetPath};
    /// let path1 = VirtualTargetPath::new("foo".into()).unwrap();
    /// let path2 = VirtualTargetPath::new("foo/bar".into()).unwrap();
    /// assert!(!path2.is_child(&path1));
    ///
    /// let path1 = VirtualTargetPath::new("foo/".into()).unwrap();
    /// let path2 = VirtualTargetPath::new("foo/bar".into()).unwrap();
    /// assert!(path2.is_child(&path1));
    ///
    /// let path2 = VirtualTargetPath::new("foo/bar/baz".into()).unwrap();
    /// assert!(path2.is_child(&path1));
    ///
    /// let path2 = VirtualTargetPath::new("wat".into()).unwrap();
    /// assert!(!path2.is_child(&path1))
    /// ```
    pub fn is_child(&self, parent: &Self) -> bool {
        if !parent.0.ends_with('/') {
            return false;
        }

        self.0.starts_with(&parent.0)
    }

    /// Whether or not the current target is available at the end of the given chain of target
    /// paths. For the chain to be valid, each target path in a group must be a child of of all
    /// previous groups.
    // TODO this is hideous and uses way too much clone/heap but I think recursively,
    // so here we are
    pub fn matches_chain(&self, parents: &[HashSet<VirtualTargetPath>]) -> bool {
        if parents.is_empty() {
            return false;
        }
        if parents.len() == 1 {
            return parents[0].iter().any(|p| p == self || self.is_child(p));
        }

        let new = parents[1..]
            .iter()
            .map(|group| {
                group
                    .iter()
                    .filter(|parent| {
                        parents[0]
                            .iter()
                            .any(|p| parent.is_child(p) || parent == &p)
                    })
                    .cloned()
                    .collect::<HashSet<_>>()
            })
            .collect::<Vec<_>>();
        self.matches_chain(&*new)
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
