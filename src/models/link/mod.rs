//! in-toto link

use std::collections::{BTreeMap};
use std::fmt::{Debug};
use std::str;

use serde_derive::{Deserialize, Serialize};
use crate::Result;

pub mod metadata;
pub use metadata::{LinkMetadata, LinkMetadataBuilder};

use crate::models::{VirtualTargetPath, TargetDescription};

// FIXME, we need to tag a spec
//const SPEC_VERSION: &str = "0.9-dev";

// FIXME: methods will be relevant for layout expiration
// fn parse_datetime(ts: &str) -> Result<DateTime<Utc>> {
//     Utc.datetime_from_str(ts, "%FT%TZ")
//         .map_err(|e| Error::Encoding(format!("Can't parse DateTime: {:?}", e)))
// }
//
// fn format_datetime(ts: &DateTime<Utc>) -> String {
//     format!(
//         "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
//         ts.year(),
//         ts.month(),
//         ts.day(),
//         ts.hour(),
//         ts.minute(),
//         ts.second()
//     )
// }

pub const FILENAME_FORMAT: &str = "{step_name}.{keyid:.8}.link";

#[derive(Debug, Serialize, Deserialize)]
pub struct Link {
    // Why is the type named as typ?
    #[serde(rename = "_type")]
    name: String,
    materials: BTreeMap<VirtualTargetPath, TargetDescription>,
    products: BTreeMap<VirtualTargetPath, TargetDescription>,
    env: BTreeMap<String, String>,
    byproducts: BTreeMap<String, String>,

}

impl Link {
    pub fn from(meta: &LinkMetadata) -> Result<Self> {
        Ok(Link {
            name: meta.name().to_string(),
            materials: (*meta.materials()).clone(),
            products: (*meta.products()).clone(),
            env: (*meta.env()).clone(),
            byproducts: (*meta.byproducts()).clone()
        })
    }

    pub fn try_into(self) -> Result<LinkMetadata> {
        LinkMetadata::new(
            self.name,
            self.materials,
            self.products,
            self.env,
            self.byproducts
        )
    }
}


