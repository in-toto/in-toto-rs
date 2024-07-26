use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{PredicateLayout, PredicateVer, PredicateWrapper};
use crate::interchange::{DataInterchange, Json};
use crate::models::byproducts::ByProducts;
use crate::models::step::Command;
use crate::models::{TargetDescription, VirtualTargetPath};
use crate::Result;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
/// Predicate `LinkV02` means the predicate of original compatible format.
///
/// [LinkV02](https://in-toto.io/Link/v0.2)
/// can be used together with most states.
pub struct LinkV02 {
    name: String,
    materials: BTreeMap<VirtualTargetPath, TargetDescription>,
    env: Option<BTreeMap<String, String>>,
    command: Command,
    byproducts: ByProducts,
}

impl PredicateLayout for LinkV02 {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Json::canonicalize(&Json::serialize(self)?)
    }

    fn into_enum(self: Box<Self>) -> PredicateWrapper {
        PredicateWrapper::LinkV0_2(*self)
    }

    fn version(&self) -> PredicateVer {
        PredicateVer::LinkV0_2
    }
}

#[cfg(test)]
pub mod test {
    use std::collections::BTreeMap;
    use std::str;

    use once_cell::sync::Lazy;
    use serde_json::{json, Value};
    use strum::IntoEnumIterator;

    use super::LinkV02;
    use crate::{
        interchange::{DataInterchange, Json},
        models::{
            byproducts::ByProducts, PredicateLayout, PredicateVer,
            PredicateWrapper,
        },
    };

    pub static STR_PREDICATE_LINK_V02: Lazy<String> = Lazy::new(|| {
        let raw_data = json!(
        {
            "byproducts": {
                "return-value": 0,
                "stderr": "",
                "stdout": ""
            },
            "command": [],
            "env": null,
            "materials": {},
            "name": ""
        });
        let value = serde_json::value::to_value(raw_data).unwrap();
        let bytes = Json::canonicalize(&value).unwrap();
        let data = str::from_utf8(&bytes).unwrap();
        data.to_string()
    });

    pub static PREDICATE_LINK_V02: Lazy<LinkV02> = Lazy::new(|| LinkV02 {
        name: "".to_string(),
        materials: BTreeMap::new(),
        env: None,
        command: "".into(),
        byproducts: ByProducts::new()
            .set_return_value(0)
            .set_stderr("".into())
            .set_stdout("".into()),
    });

    #[test]
    fn into_trait_equal() {
        let predicate = PredicateWrapper::LinkV0_2(PREDICATE_LINK_V02.clone());
        let real = Box::new(PREDICATE_LINK_V02.clone()).into_enum();

        assert_eq!(predicate, real);
    }

    #[test]
    fn create_predicate_from_meta() {
        // TODO: convert from metadata is no supported recentely
    }

    #[test]
    fn serialize_predicate() {
        let predicate = Box::new(PREDICATE_LINK_V02.clone()).into_enum();
        let buf = predicate.into_trait().to_bytes().unwrap();
        let predicate_serialized = str::from_utf8(&buf).unwrap();

        assert_eq!(predicate_serialized, *STR_PREDICATE_LINK_V02);
    }

    #[test]
    fn deserialize_predicate() {
        let value: Value =
            serde_json::from_str(&STR_PREDICATE_LINK_V02).unwrap();
        let predicate =
            PredicateWrapper::from_value(value, PredicateVer::LinkV0_2)
                .unwrap();
        let real = Box::new(PREDICATE_LINK_V02.clone()).into_enum();

        assert_eq!(predicate, real);
    }

    #[test]
    fn deserialize_auto() {
        let value: Value =
            serde_json::from_str(&STR_PREDICATE_LINK_V02).unwrap();
        let predicate = PredicateWrapper::try_from_value(value).unwrap();
        let real = Box::new(PREDICATE_LINK_V02.clone()).into_enum();

        assert_eq!(predicate, real);
    }

    #[test]
    fn deserialize_dismatch() {
        let value: Value =
            serde_json::from_str(&STR_PREDICATE_LINK_V02).unwrap();
        for version in PredicateVer::iter() {
            if version == PredicateVer::LinkV0_2 {
                continue;
            }
            let predicate =
                PredicateWrapper::from_value(value.clone(), version);

            assert!(predicate.is_err());
        }
    }
}
