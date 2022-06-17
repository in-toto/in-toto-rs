//! in-toto layoput metadata.

use chrono::{DateTime, Duration, Utc};
use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use serde::ser::{Error as SerializeError, Serialize, Serializer};

use std::collections::HashMap;

use crate::crypto::KeyId;
use crate::Result;
use crate::{crypto::PublicKey, models::Metadata};

use super::Layout;
use super::{inspection::Inspection, step::Step};

/// Helper to construct `LayoutMetadata`
pub struct LayoutMetadataBuilder {
    expires: DateTime<Utc>,
    readme: String,
    keys: HashMap<KeyId, PublicKey>,
    steps: Vec<Step>,
    inspect: Vec<Inspection>,
}

impl Default for LayoutMetadataBuilder {
    fn default() -> Self {
        LayoutMetadataBuilder::new()
    }
}

impl LayoutMetadataBuilder {
    /// Create a new `LayoutMetadataBuilder`. It defaults to:
    ///
    /// * expires: 365 days from the current time.
    /// * readme: ""
    pub fn new() -> Self {
        LayoutMetadataBuilder {
            steps: Vec::new(),
            inspect: Vec::new(),
            keys: HashMap::new(),
            expires: Utc::now() + Duration::days(365),
            readme: String::new(),
        }
    }

    /// Add new step to this layout
    pub fn add_step(mut self, step: Step) -> Self {
        self.steps.push(step);
        self
    }

    /// Add new steps to this layout
    pub fn add_steps(mut self, mut steps: Vec<Step>) -> Self {
        self.steps.append(&mut steps);
        self
    }

    /// Set steps to this layout
    pub fn steps(mut self, steps: Vec<Step>) -> Self {
        self.steps = steps;
        self
    }

    /// Add new inspect to this layout
    pub fn add_inspect(mut self, inspect: Inspection) -> Self {
        self.inspect.push(inspect);
        self
    }

    /// Add new inspects to this layout
    pub fn add_inspects(mut self, mut inspects: Vec<Inspection>) -> Self {
        self.inspect.append(&mut inspects);
        self
    }

    /// Set inspects to this layout
    pub fn inspects(mut self, step: Vec<Inspection>) -> Self {
        self.inspect = step;
        self
    }

    /// Add a new pubkey to this layout
    pub fn add_key(mut self, key: PublicKey) -> Self {
        self.keys.insert(key.key_id().clone(), key);
        self
    }

    pub fn build(self) -> Result<LayoutMetadata> {
        Ok(LayoutMetadata::new(
            self.expires,
            self.readme,
            self.keys,
            self.steps,
            self.inspect,
        ))
    }
}

/// layout metadata
#[derive(Debug, Clone, PartialEq)]
pub struct LayoutMetadata {
    steps: Vec<Step>,
    inspect: Vec<Inspection>,
    keys: HashMap<KeyId, PublicKey>,
    expires: DateTime<Utc>,
    readme: String,
}

impl LayoutMetadata {
    pub fn new(
        expires: DateTime<Utc>,
        readme: String,
        keys: HashMap<KeyId, PublicKey>,
        steps: Vec<Step>,
        inspect: Vec<Inspection>,
    ) -> Self {
        LayoutMetadata {
            steps,
            inspect,
            keys,
            expires,
            readme,
        }
    }

    /// Restrictions for each step within the supply chain
    pub fn steps(&self) -> &Vec<Step> {
        &self.steps
    }

    /// Inspecting is done by the client upon verification
    pub fn inspect(&self) -> &Vec<Inspection> {
        &self.inspect
    }

    /// All the public keys used in the steps section
    pub fn keys(&self) -> &HashMap<KeyId, PublicKey> {
        &self.keys
    }

    /// The expired time this layout is associated to
    pub fn expires(&self) -> &DateTime<Utc> {
        &self.expires
    }

    /// A human-readable description of this supply chain
    pub fn readme(&self) -> &String {
        &self.readme
    }
}

impl Metadata for LayoutMetadata {
    // Follow in-toto spec v0.9
    fn version(&self) -> u32 {
        0u32
    }
}

impl Serialize for LayoutMetadata {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Layout::from(self)
            .map_err(|e| SerializeError::custom(format!("{:?}", e)))?
            .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for LayoutMetadata {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: Layout = Deserialize::deserialize(de)?;
        intermediate
            .try_into()
            .map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}
