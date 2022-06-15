//! in-toto layout: used by the project owner to generate a desired supply chain layout file.

use std::collections::BTreeMap;

use chrono::prelude::*;
use chrono::TimeZone;
use chrono::{DateTime, Utc};
use serde_derive::{Deserialize, Serialize};

use crate::crypto::{KeyId, PublicKey};
use crate::{Error, Result};

use self::{inspection::Inspection, step::Step};

pub mod inspection;
pub mod metadata;
pub mod step;

pub use metadata::{LayoutMetadata, LayoutMetadataBuilder};

#[derive(Debug, Serialize, Deserialize)]
pub struct Layout {
    expires: String,
    readme: String,
    keys: BTreeMap<KeyId, PublicKey>,
    steps: Vec<Step>,
    inspect: Vec<Inspection>,
}

impl Layout {
    pub fn from(meta: &LayoutMetadata) -> Result<Self> {
        Ok(Layout {
            expires: format_datetime(meta.expires()),
            readme: meta.readme().to_string(),
            keys: meta
                .keys()
                .iter()
                .map(|(id, key)| (id.clone(), key.clone()))
                .collect(),
            steps: (*meta.steps()).clone(),
            inspect: (*meta.inspect()).clone(),
        })
    }

    pub fn try_into(self) -> Result<LayoutMetadata> {
        // Ignore all keys with incorrect key IDs.
        let keys_with_correct_key_id = self
            .keys
            .into_iter()
            .filter(|(key_id, pkey)| key_id == pkey.key_id())
            .collect();

        Ok(LayoutMetadata::new(
            parse_datetime(&self.expires)?,
            self.readme,
            keys_with_correct_key_id,
            self.steps,
            self.inspect,
        ))
    }
}

fn parse_datetime(ts: &str) -> Result<DateTime<Utc>> {
    Utc.datetime_from_str(ts, "%FT%TZ")
        .map_err(|e| Error::Encoding(format!("Can't parse DateTime: {:?}", e)))
}

fn format_datetime(ts: &DateTime<Utc>) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        ts.year(),
        ts.month(),
        ts.day(),
        ts.hour(),
        ts.minute(),
        ts.second()
    )
}
