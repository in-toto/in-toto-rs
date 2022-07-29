//! in-toto link

pub mod link_v02;
pub mod proven_v01;
pub mod proven_v02;
pub use link_v02::LinkV02;
pub use proven_v01::ProvenV01;
pub use proven_v02::ProvenV02;

use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use serde::ser::{Error as SerializeError, Serialize, Serializer};
use serde_derive::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use super::Convert;
use super::LinkMetadata;
use crate::{Error, Result};

#[derive(Debug, Hash, PartialEq, EnumIter, Clone, Copy)]
pub enum PredicateVersion {
    LinkV0_2,
    ProvenV0_1,
    ProvenV0_2,
}

impl Convert<String> for PredicateVersion {
    fn try_from(target: String) -> Result<Self> {
        match target.as_str() {
            "https://in-toto.io/Link/v0.2" => Ok(PredicateVersion::LinkV0_2),
            "https://slsa.dev/provenance/v0.1" => Ok(PredicateVersion::ProvenV0_1),
            "https://slsa.dev/provenance/v0.2" => Ok(PredicateVersion::ProvenV0_2),
            _ => Err(Error::StringConvertFailed(target)),
        }
    }

    fn try_into(self) -> Result<String> {
        match self {
            PredicateVersion::LinkV0_2 => Ok("https://in-toto.io/Link/v0.2".to_string()),
            PredicateVersion::ProvenV0_1 => Ok("https://slsa.dev/provenance/v0.1".to_string()),
            PredicateVersion::ProvenV0_2 => Ok("https://slsa.dev/provenance/v0.2".to_string()),
        }
    }
}

impl Serialize for PredicateVersion {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let target = &self
            .try_into()
            .map_err(|e| SerializeError::custom(format!("{:?}", e)))?;
        ser.serialize_str(target)
    }
}

impl<'de> Deserialize<'de> for PredicateVersion {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let target: String = Deserialize::deserialize(de)?;
        PredicateVersion::try_from(target).map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(untagged)]
pub enum PredicateWrapper {
    LinkV0_2(LinkV02),
    ProvenV0_1(ProvenV01),
    ProvenV0_2(ProvenV02),
}

impl PredicateWrapper {
    /// Convert from enum `PredicateWrapper` to trait `PredicateLayout`
    pub fn into_trait(self) -> Box<dyn PredicateLayout> {
        match self {
            PredicateWrapper::LinkV0_2(link) => Box::new(link),
            PredicateWrapper::ProvenV0_1(proven) => Box::new(proven),
            PredicateWrapper::ProvenV0_2(proven) => Box::new(proven),
        }
    }

    /// Construct `PredicateWrapper` from MetaData
    pub fn from_meta(meta: LinkMetadata, version: PredicateVersion) -> Self {
        match version {
            PredicateVersion::LinkV0_2 => Self::LinkV0_2(LinkV02::from(meta)),
            PredicateVersion::ProvenV0_1 => Self::ProvenV0_1(ProvenV01::from(meta)),
            PredicateVersion::ProvenV0_2 => Self::ProvenV0_2(ProvenV02::from(meta)),
        }
    }

    /// Standard deserialize for PredicateWrapper by its version
    pub fn from_bytes(bytes: &[u8], version: PredicateVersion) -> Result<Self> {
        match version {
            PredicateVersion::LinkV0_2 => serde_json::from_slice(bytes)
                .map(Self::LinkV0_2)
                .map_err(|e| e.into()),
            PredicateVersion::ProvenV0_1 => serde_json::from_slice(bytes)
                .map(Self::ProvenV0_1)
                .map_err(|e| e.into()),
            PredicateVersion::ProvenV0_2 => serde_json::from_slice(bytes)
                .map(Self::ProvenV0_2)
                .map_err(|e| e.into()),
        }
    }

    /// Auto deserialize for PredicateWrapper by any possible version.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut link: Result<PredicateWrapper> =
            Err(Error::Programming("no available bytes parser".to_string()));
        for version in PredicateVersion::iter() {
            link = PredicateWrapper::from_bytes(bytes, version);
            if link.is_ok() {
                break;
            }
        }
        link
    }
}

pub trait PredicateLayout {
    /// The version of predicate
    fn version(&self) -> PredicateVersion;
    /// Convert from trait `PredicateLayout` to enum `PredicateWrapper`
    fn into_enum(self: Box<Self>) -> PredicateWrapper;
    /// Standard serialize for PredicateLayout
    fn to_bytes(&self) -> Result<Vec<u8>>;
}
