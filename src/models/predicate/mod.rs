//! in-toto link

pub mod link_v02;
pub mod slsa_provenance_v01;
pub mod slsa_provenance_v02;
use std::convert::TryFrom;

pub use link_v02::LinkV02;
use serde_json::Value;
pub use slsa_provenance_v01::SLSAProvenanceV01;
pub use slsa_provenance_v02::SLSAProvenanceV02;

use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use serde::ser::{Serialize, Serializer};
use serde_derive::Serialize;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::{Error, Result};

#[derive(Debug, Hash, PartialEq, Eq, EnumIter, Clone, Copy)]
pub enum PredicateVer {
    LinkV0_2,
    SLSAProvenanceV0_1,
    SLSAProvenanceV0_2,
}

impl TryFrom<String> for PredicateVer {
    type Error = crate::Error;

    fn try_from(target: String) -> Result<Self> {
        match target.as_str() {
            "https://in-toto.io/Link/v0.2" => Ok(PredicateVer::LinkV0_2),
            "https://slsa.dev/provenance/v0.1" => {
                Ok(PredicateVer::SLSAProvenanceV0_1)
            }
            "https://slsa.dev/provenance/v0.2" => {
                Ok(PredicateVer::SLSAProvenanceV0_2)
            }
            _ => Err(Error::StringConvertFailed(target)),
        }
    }
}

impl From<PredicateVer> for String {
    fn from(value: PredicateVer) -> Self {
        match value {
            PredicateVer::LinkV0_2 => {
                "https://in-toto.io/Link/v0.2".to_string()
            }
            PredicateVer::SLSAProvenanceV0_1 => {
                "https://slsa.dev/provenance/v0.1".to_string()
            }
            PredicateVer::SLSAProvenanceV0_2 => {
                "https://slsa.dev/provenance/v0.2".to_string()
            }
        }
    }
}

impl Serialize for PredicateVer {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let target: String = (*self).into();
        ser.serialize_str(&target)
    }
}

impl<'de> Deserialize<'de> for PredicateVer {
    fn deserialize<D: Deserializer<'de>>(
        de: D,
    ) -> ::std::result::Result<Self, D::Error> {
        let target: String = Deserialize::deserialize(de)?;
        PredicateVer::try_from(target)
            .map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

#[derive(Debug, Serialize, PartialEq, Eq, Clone)]
#[serde(untagged)]
pub enum PredicateWrapper {
    LinkV0_2(LinkV02),
    SLSAProvenanceV0_1(SLSAProvenanceV01),
    SLSAProvenanceV0_2(SLSAProvenanceV02),
}

impl<'de> Deserialize<'de> for PredicateWrapper {
    fn deserialize<D: Deserializer<'de>>(
        de: D,
    ) -> ::std::result::Result<Self, D::Error> {
        let value = Value::deserialize(de)?;
        PredicateWrapper::try_from_value(value)
            .map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
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

    /// Deserialize method for `PredicateWrapper` from `serde:Value` by its version
    fn from_value(value: Value, version: PredicateVer) -> Result<Self> {
        match version {
            PredicateVer::LinkV0_2 => serde_json::from_value(value)
                .map(Self::LinkV0_2)
                .map_err(|e| e.into()),
            PredicateVer::SLSAProvenanceV0_1 => serde_json::from_value(value)
                .map(Self::SLSAProvenanceV0_1)
                .map_err(|e| e.into()),
            PredicateVer::SLSAProvenanceV0_2 => serde_json::from_value(value)
                .map(Self::SLSAProvenanceV0_2)
                .map_err(|e| e.into()),
        }
    }

    /// Auto judge the `PredicateWrapper` version from `serde:Value`
    pub fn judge_from_value(value: &Value) -> Result<PredicateVer> {
        println!("{:?}", value);
        for version in PredicateVer::iter() {
            let wrapper = PredicateWrapper::from_value(value.clone(), version);
            if wrapper.is_ok() {
                return Ok(version);
            }
        }
        Err(Error::Programming("no available value parser".to_string()))
    }

    /// Auto deserialize for `PredicateWrapper` by any possible version.
    pub fn try_from_value(value: Value) -> Result<Self> {
        let version = Self::judge_from_value(&value)?;
        PredicateWrapper::from_value(value, version)
    }
}

pub trait PredicateLayout {
    /// The version of predicate
    fn version(&self) -> PredicateVer;
    /// Convert from trait `PredicateLayout` to enum `PredicateWrapper`
    fn into_enum(self: Box<Self>) -> PredicateWrapper;
    /// Standard serialize for PredicateLayout
    fn to_bytes(&self) -> Result<Vec<u8>>;
}
