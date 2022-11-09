pub mod state_naive;
pub mod state_v01;
use serde_json::Value;
pub use state_naive::StateNaive;
pub use state_v01::StateV01;

use std::convert::TryFrom;
use std::fmt::{Display, Formatter, Result as FmtResult};

use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use serde::ser::{Serialize, Serializer};
use serde_derive::Serialize;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use super::{LinkMetadata, PredicateLayout};
use crate::Error;
use crate::Result;

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, EnumIter)]
pub enum StatementVer {
    Naive,
    V0_1,
}

impl TryFrom<String> for StatementVer {
    type Error = crate::Error;

    fn try_from(target: String) -> Result<Self> {
        match target.as_str() {
            "link" => Ok(StatementVer::Naive),
            "https://in-toto.io/Statement/v0.1" => Ok(StatementVer::V0_1),
            _ => Err(Error::StringConvertFailed(target)),
        }
    }
}

impl From<StatementVer> for String {
    fn from(value: StatementVer) -> Self {
        match value {
            StatementVer::Naive => "link".to_string(),
            StatementVer::V0_1 => "https://in-toto.io/Statement/v0.1".to_string(),
        }
    }
}

impl Serialize for StatementVer {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let target: String = (*self).into();
        ser.serialize_str(&target)
    }
}

impl<'de> Deserialize<'de> for StatementVer {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let target: String = Deserialize::deserialize(de)?;
        StatementVer::try_from(target).map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

impl Display for StatementVer {
    fn fmt(&self, fmt: &mut Formatter) -> FmtResult {
        match self {
            StatementVer::V0_1 => fmt.write_str("v0.1")?,
            StatementVer::Naive => fmt.write_str("naive")?,
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub enum StatementWrapper {
    Naive(StateNaive),
    V0_1(StateV01),
}
impl<'de> Deserialize<'de> for StatementWrapper {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let value = Value::deserialize(de)?;
        StatementWrapper::try_from_value(value)
            .map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

pub trait FromMerge: Sized {
    fn merge(meta: LinkMetadata, predicate: Option<Box<dyn PredicateLayout>>) -> Result<Self>;
}

impl StatementWrapper {
    pub fn into_trait(self) -> Box<dyn StateLayout> {
        match self {
            StatementWrapper::Naive(link) => Box::new(link),
            StatementWrapper::V0_1(link) => Box::new(link),
        }
    }

    pub fn from_meta(
        meta: LinkMetadata,
        predicate: Option<Box<dyn PredicateLayout>>,
        version: StatementVer,
    ) -> Self {
        match version {
            StatementVer::Naive => Self::Naive(StateNaive::merge(meta, predicate).unwrap()),
            StatementVer::V0_1 => Self::V0_1(StateV01::merge(meta, predicate).unwrap()),
        }
    }

    /// Deserialize method for `StatementWrapper` from `serde:Value` by its version
    fn from_value(value: Value, version: StatementVer) -> Result<Self> {
        match version {
            StatementVer::Naive => serde_json::from_value(value)
                .map(Self::Naive)
                .map_err(|e| e.into()),
            StatementVer::V0_1 => serde_json::from_value(value)
                .map(Self::V0_1)
                .map_err(|e| e.into()),
        }
    }

    /// Auto judge the `PredicateWrapper` version from `serde:Value`
    pub fn judge_from_value(value: &Value) -> Result<StatementVer> {
        for version in StatementVer::iter() {
            let wrapper = StatementWrapper::from_value(value.clone(), version);
            if wrapper.is_ok() {
                return Ok(version);
            }
        }
        Err(Error::Programming("no available value parser".to_string()))
    }

    /// Auto deserialize for `PredicateWrapper` by any possible version.
    pub fn try_from_value(value: Value) -> Result<Self> {
        let version = Self::judge_from_value(&value)?;
        StatementWrapper::from_value(value, version)
    }
}

pub trait StateLayout {
    fn version(&self) -> StatementVer;
    fn into_enum(self: Box<Self>) -> StatementWrapper;
    fn to_bytes(&self) -> Result<Vec<u8>>;
}
