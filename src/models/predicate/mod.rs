//! in-toto link

pub mod link_v02;
pub mod slsa_provenance_v01;
pub mod slsa_provenance_v02;
pub use link_v02::LinkV02;
pub use slsa_provenance_v01::SLSAProvenanceV01;
pub use slsa_provenance_v02::SLSAProvenanceV02;

use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use serde::ser::{Error as SerializeError, Serialize, Serializer};
use serde_derive::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use super::Convert;
use crate::{Error, Result};

#[derive(Debug, Hash, PartialEq, EnumIter, Clone, Copy)]
pub enum PredicateVersion {
    LinkV0_2,
    SLSAProvenanceV0_1,
    SLSAProvenanceV0_2,
}

impl Convert<String> for PredicateVersion {
    fn try_from(target: String) -> Result<Self> {
        match target.as_str() {
            "https://in-toto.io/Link/v0.2" => Ok(PredicateVersion::LinkV0_2),
            "https://slsa.dev/provenance/v0.1" => Ok(PredicateVersion::SLSAProvenanceV0_1),
            "https://slsa.dev/provenance/v0.2" => Ok(PredicateVersion::SLSAProvenanceV0_2),
            _ => Err(Error::StringConvertFailed(target)),
        }
    }

    fn try_into(self) -> Result<String> {
        match self {
            PredicateVersion::LinkV0_2 => Ok("https://in-toto.io/Link/v0.2".to_string()),
            PredicateVersion::SLSAProvenanceV0_1 => {
                Ok("https://slsa.dev/provenance/v0.1".to_string())
            }
            PredicateVersion::SLSAProvenanceV0_2 => {
                Ok("https://slsa.dev/provenance/v0.2".to_string())
            }
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
    SLSAProvenanceV0_1(SLSAProvenanceV01),
    SLSAProvenanceV0_2(SLSAProvenanceV02),
}

impl PredicateWrapper {
    /// Convert from enum `PredicateWrapper` to trait `PredicateLayout`
    pub fn into_trait(self) -> Box<dyn PredicateLayout> {
        match self {
            PredicateWrapper::LinkV0_2(link) => Box::new(link),
            PredicateWrapper::SLSAProvenanceV0_1(proven) => Box::new(proven),
            PredicateWrapper::SLSAProvenanceV0_2(proven) => Box::new(proven),
        }
    }

    /// Standard deserialize for PredicateWrapper by its version
    pub fn from_bytes(bytes: &[u8], version: PredicateVersion) -> Result<Self> {
        match version {
            PredicateVersion::LinkV0_2 => serde_json::from_slice(bytes)
                .map(Self::LinkV0_2)
                .map_err(|e| e.into()),
            PredicateVersion::SLSAProvenanceV0_1 => serde_json::from_slice(bytes)
                .map(Self::SLSAProvenanceV0_1)
                .map_err(|e| e.into()),
            PredicateVersion::SLSAProvenanceV0_2 => serde_json::from_slice(bytes)
                .map(Self::SLSAProvenanceV0_2)
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
