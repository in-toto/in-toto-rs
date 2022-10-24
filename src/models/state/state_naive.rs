use std::{collections::BTreeMap, fmt::Debug};

use serde_derive::{Deserialize, Serialize};

use super::{FromMerge, StateLayout, StateWrapper, StatementVer};
use crate::models::{LinkMetadata, TargetDescription, VirtualTargetPath};
use crate::{
    interchange::{DataInterchange, Json},
    models::{byproducts::ByProducts, step::Command, Convert, PredicateLayout},
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

impl FromMerge for StateNaive {
    fn merge(
        meta: LinkMetadata,
        predicate: Option<Box<dyn PredicateLayout>>,
    ) -> Result<StateNaive> {
        if let Some(p) = predicate {
            return Err(Error::AttestationFormatDismatch(
                "None".to_string(),
                p.version().try_into()?,
            ));
        };
        let version = StatementVer::Naive.try_into()?;
        Ok(StateNaive {
            typ: version,
            name: meta.name().to_string(),
            materials: meta.materials().clone(),
            products: meta.products().clone(),
            env: meta.env().clone(),
            command: meta.command().clone(),
            byproducts: meta.byproducts().clone(),
        })
    }
}

impl StateLayout for StateNaive {
    fn version(&self) -> StatementVer {
        StatementVer::Naive
    }

    fn into_enum(self: Box<Self>) -> StateWrapper {
        StateWrapper::Naive(*self)
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        Json::canonicalize(&Json::serialize(self)?)
    }
}

#[cfg(test)]
pub mod test {
    use std::collections::BTreeMap;
    use std::str;

    use once_cell::sync::Lazy;
    use serde_json::json;
    use strum::IntoEnumIterator;

    use super::StateNaive;
    use crate::interchange::{DataInterchange, Json};
    use crate::models::byproducts::ByProducts;
    use crate::models::state::{StateLayout, StateWrapper, StatementVer};
    use crate::models::test::BLANK_META;
    use crate::models::Convert;

    pub static STR_NAIVE: Lazy<String> = Lazy::new(|| {
        let raw_data = json!({
            "_type": "link",
            "byproducts": {
                "return-value": 0,
                "stderr": "",
                "stdout": ""
            },
            "command": "",
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
        typ: StatementVer::Naive.try_into().unwrap(),
        name: "".to_string(),
        materials: BTreeMap::new(),
        products: BTreeMap::new(),
        env: None,
        command: "".into(),
        byproducts: ByProducts::new(),
    });

    #[test]
    fn into_trait_equal() {
        let state = StateWrapper::Naive(STATE_NAIVE.clone());
        let real = Box::new(STATE_NAIVE.clone()).into_enum();

        assert_eq!(state, real);
    }

    #[test]
    fn create_state_from_meta() {
        let state = StateWrapper::from_meta(BLANK_META.clone(), None, StatementVer::Naive);
        let real = Box::new(STATE_NAIVE.clone()).into_enum();

        assert_eq!(state, real);
    }

    #[test]
    fn serialize_state() {
        let state = Box::new(STATE_NAIVE.clone()).into_enum();
        let buf = state.into_trait().to_bytes().unwrap();
        let link_serialized = str::from_utf8(&buf).unwrap();

        assert_eq!(link_serialized, *STR_NAIVE);
    }

    #[test]
    fn deserialize_state() {
        let link =
            StateWrapper::from_bytes(STR_NAIVE.as_bytes().to_vec(), StatementVer::Naive).unwrap();
        let real = Box::new(STATE_NAIVE.clone()).into_enum();

        assert_eq!(link, real);
    }

    #[test]
    fn deserialize_auto() {
        let link = StateWrapper::try_from_bytes(STR_NAIVE.as_bytes().to_vec()).unwrap();
        let real = Box::new(STATE_NAIVE.clone()).into_enum();

        assert_eq!(link, real);
    }

    #[test]
    fn deserialize_dismatch() {
        for version in StatementVer::iter() {
            if version == StatementVer::Naive {
                continue;
            }
            let state = StateWrapper::from_bytes(STR_NAIVE.as_bytes().to_vec(), version);

            assert!(state.is_err());
        }
    }
}
