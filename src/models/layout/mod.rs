//! in-toto layout: used by the project owner to generate a desired supply chain layout file.

use std::collections::BTreeMap;

use chrono::prelude::*;
use chrono::TimeZone;
use chrono::{DateTime, Utc};
use log::warn;
use serde_derive::{Deserialize, Serialize};

use crate::crypto::{KeyId, PublicKey};
use crate::{Error, Result};

use self::{inspection::Inspection, step::Step};

pub mod inspection;
pub mod metadata;
pub mod rule;
pub mod step;
pub mod supply_chain_item;

pub use metadata::{LayoutMetadata, LayoutMetadataBuilder};

#[derive(Debug, Serialize, Deserialize)]
pub struct Layout {
    #[serde(rename = "_type")]
    typ: String,
    expires: String,
    readme: String,
    keys: BTreeMap<KeyId, PublicKey>,
    steps: Vec<Step>,
    inspect: Vec<Inspection>,
}

impl Layout {
    pub fn from(meta: &LayoutMetadata) -> Result<Self> {
        Ok(Layout {
            typ: String::from("layout"),
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
        // If a malformed key is used, there will be a warning
        let keys_with_correct_key_id = self
            .keys
            .into_iter()
            .filter(|(key_id, pkey)| match key_id == pkey.key_id() {
                true => true,
                false => {
                    warn!("Malformed key of ID {:?}", key_id);
                    false
                }
            })
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
    ts.to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod test {
    use chrono::{DateTime, NaiveDateTime, Utc};

    use crate::models::layout::format_datetime;

    use super::parse_datetime;

    #[test]
    fn parse_datetime_test() {
        let time_str = "1970-01-01T00:00:00Z".to_string();
        let parsed_dt = parse_datetime(&time_str[..]).unwrap();
        let dt = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc);
        assert_eq!(parsed_dt, dt);
    }

    #[test]
    fn format_datetime_test() {
        let dt = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc);
        let generated_dt_str = format_datetime(&dt);
        let dt_str = "1970-01-01T00:00:00Z".to_string();
        assert_eq!(dt_str, generated_dt_str);
    }
}
