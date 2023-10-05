use std::{collections::BTreeMap, fmt::Debug};

use serde_derive::{Deserialize, Serialize};

use super::{FromMerge, StateLayout, StatementVer, StatementWrapper};
use crate::models::{LinkMetadata, TargetDescription, VirtualTargetPath};
use crate::{
    interchange::{DataInterchange, Json},
    models::{byproducts::ByProducts, step::Command, PredicateLayout},
    Error, Result,
};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// Statement `Naive` means the predicate of original format.
///
/// Can be used together with no predicate as `None`.
pub struct StateNaive {
    #[serde(rename = "_type")]
    typ: String,
    name: String,
    materials: BTreeMap<VirtualTargetPath, TargetDescription>,
    products: BTreeMap<VirtualTargetPath, TargetDescription>,
    env: Option<BTreeMap<String, String>>,
    command: Command,
    byproducts: ByProducts,
}

impl StateLayout for StateNaive {
    fn version(&self) -> StatementVer {
        StatementVer::Naive
    }

    fn into_enum(self: Box<Self>) -> StatementWrapper {
        StatementWrapper::Naive(*self)
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        Json::canonicalize(&Json::serialize(self)?)
    }
}

impl FromMerge for StateNaive {
    fn merge(
        meta: LinkMetadata,
        predicate: Option<Box<dyn PredicateLayout>>,
    ) -> Result<StateNaive> {
        if let Some(p) = predicate {
            return Err(Error::AttestationFormatDismatch(
                "None".to_string(),
                p.version().into(),
            ));
        };
        let version = StatementVer::Naive.into();
        Ok(StateNaive {
            typ: version,
            name: meta.name,
            materials: meta.materials,
            products: meta.products,
            env: meta.env,
            command: meta.command,
            byproducts: meta.byproducts,
        })
    }
}

#[cfg(test)]
pub mod test {
    use std::collections::BTreeMap;
    use std::str;

    use once_cell::sync::Lazy;
    use serde_json::{json, Value};
    use strum::IntoEnumIterator;

    use super::StateNaive;
    use crate::interchange::{DataInterchange, Json};
    use crate::models::byproducts::ByProducts;
    use crate::models::statement::{
        StateLayout, StatementVer, StatementWrapper,
    };
    use crate::models::test::BLANK_META;

    pub static STR_NAIVE: Lazy<String> = Lazy::new(|| {
        let raw_data = json!({
            "_type": "link",
            "byproducts": {},
            "command": [],
            "env": null,
            "materials": {},
            "name": "",
            "products": {}
        });
        let value = serde_json::value::to_value(raw_data).unwrap();
        let bytes = Json::canonicalize(&value).unwrap();
        let data = str::from_utf8(&bytes).unwrap();
        data.to_string()
    });

    pub static STATE_NAIVE: Lazy<StateNaive> = Lazy::new(|| StateNaive {
        typ: StatementVer::Naive.into(),
        name: "".to_string(),
        materials: BTreeMap::new(),
        products: BTreeMap::new(),
        env: None,
        command: "".into(),
        byproducts: ByProducts::new(),
    });

    #[test]
    fn into_trait_equal() {
        let state = StatementWrapper::Naive(STATE_NAIVE.clone());
        let real = Box::new(STATE_NAIVE.clone()).into_enum();

        assert_eq!(state, real);
    }

    #[test]
    fn create_statement_from_meta() {
        let state = StatementWrapper::from_meta(
            BLANK_META.clone(),
            None,
            StatementVer::Naive,
        );
        let real = Box::new(STATE_NAIVE.clone()).into_enum();

        assert_eq!(state, real);
    }

    #[test]
    fn serialize_statement() {
        let state = Box::new(STATE_NAIVE.clone()).into_enum();
        let buf = state.into_trait().to_bytes().unwrap();
        let link_serialized = str::from_utf8(&buf).unwrap();

        assert_eq!(link_serialized, *STR_NAIVE);
    }

    #[test]
    fn deserialize_statement() {
        let value: Value = serde_json::from_str(&STR_NAIVE).unwrap();
        let link =
            StatementWrapper::from_value(value, StatementVer::Naive).unwrap();
        let real = Box::new(STATE_NAIVE.clone()).into_enum();

        assert_eq!(link, real);
    }

    #[test]
    fn deserialize_auto() {
        let value: Value = serde_json::from_str(&STR_NAIVE).unwrap();
        let link = StatementWrapper::try_from_value(value).unwrap();
        let real = Box::new(STATE_NAIVE.clone()).into_enum();

        assert_eq!(link, real);
    }

    #[test]
    fn deserialize_dismatch() {
        let value: Value = serde_json::from_str(&STR_NAIVE).unwrap();
        for version in StatementVer::iter() {
            if version == StatementVer::Naive {
                continue;
            }
            let state = StatementWrapper::from_value(value.clone(), version);

            assert!(state.is_err());
        }
    }
}
