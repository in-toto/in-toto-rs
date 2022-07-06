//! in-toto link

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::str;

use crate::Result;
use serde_derive::{Deserialize, Serialize};

pub mod byproducts;
pub mod metadata;
pub use metadata::{LinkMetadata, LinkMetadataBuilder};

use crate::models::{TargetDescription, VirtualTargetPath};

use self::byproducts::ByProducts;

use super::step::Command;

// FIXME, we need to tag a spec
//const SPEC_VERSION: &str = "0.9-dev";

#[derive(Debug, Serialize, Deserialize)]
pub struct Link {
    #[serde(rename = "_type")]
    typ: String,
    name: String,
    materials: BTreeMap<VirtualTargetPath, TargetDescription>,
    products: BTreeMap<VirtualTargetPath, TargetDescription>,
    env: Option<BTreeMap<String, String>>,
    byproducts: ByProducts,
    command: Command,
}

impl Link {
    pub fn from(meta: &LinkMetadata) -> Result<Self> {
        Ok(Link {
            typ: String::from("link"),
            name: meta.name().to_string(),
            materials: (*meta.materials()).clone(),
            products: (*meta.products()).clone(),
            env: (*meta.env()).clone(),
            byproducts: (*meta.byproducts()).clone(),
            command: (*meta.command()).clone(),
        })
    }

    pub fn try_into(self) -> Result<LinkMetadata> {
        LinkMetadata::new(
            self.name,
            self.materials,
            self.products,
            self.env,
            self.byproducts,
            self.command,
        )
    }
}
