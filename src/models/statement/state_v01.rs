use std::collections::BTreeMap;

use serde_derive::{Deserialize, Serialize};

use crate::{
    interchange::{DataInterchange, Json},
    models::{
        LinkMetadata, PredicateLayout, PredicateVer, PredicateWrapper, TargetDescription,
        VirtualTargetPath,
    },
    Error,
};

use super::{FromMerge, StateLayout, StatementVer, StatementWrapper};
use crate::Result;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
/// Statement `V0_1` means the statement of contains a predicate for SLSA format.
///
/// Can be used together with most predicate.
pub struct StateV01 {
    #[serde(rename = "_type")]
    typ: String,
    subject: BTreeMap<VirtualTargetPath, TargetDescription>,
    #[serde(rename = "predicateType")]
    predicate_type: PredicateVer,
    predicate: PredicateWrapper,
}

impl StateLayout for StateV01 {
    fn version(&self) -> StatementVer {
        StatementVer::V0_1
    }

    fn into_enum(self: Box<Self>) -> StatementWrapper {
        StatementWrapper::V0_1(*self)
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        Json::canonicalize(&Json::serialize(self)?)
    }
}

impl FromMerge for StateV01 {
    fn merge(meta: LinkMetadata, predicate: Option<Box<dyn PredicateLayout>>) -> Result<StateV01> {
        if predicate.is_none() {
            return Err(Error::AttestationFormatDismatch(
                StatementVer::V0_1.to_string(),
                "None".to_string(),
            ));
        }
        let p = predicate
            .ok_or_else(|| Error::Programming("match rules failed for StateV01".to_string()))?;
        let version = StatementVer::V0_1.into();
        Ok(StateV01 {
            typ: version,
            subject: meta.products,
            predicate_type: p.version(),
            predicate: p.into_enum(),
        })
    }
}

#[cfg(test)]
pub mod test {
    use crate::{
        interchange::{DataInterchange, Json},
        models::{
            predicate::link_v02::test::PREDICATE_LINK_V02,
            statement::{StateLayout, StatementVer, StatementWrapper},
            test::BLANK_META,
            PredicateLayout, PredicateVer,
        },
    };
    use std::collections::BTreeMap;
    use std::str;

    use once_cell::sync::Lazy;
    use serde_json::{json, Value};
    use strum::IntoEnumIterator;

    use super::StateV01;

    pub static STR_V01: Lazy<String> = Lazy::new(|| {
        let raw_data = json!({
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://in-toto.io/Link/v0.2",
            "predicate": {
                "byproducts": {
                    "return-value": 0,
                    "stderr": "",
                    "stdout": ""
                },
                "command": [],
                "env": null,
                "materials": {},
                "name": ""
            },
            "subject": {}
        });
        let value = serde_json::value::to_value(raw_data).unwrap();
        let bytes = Json::canonicalize(&value).unwrap();
        let data = str::from_utf8(&bytes).unwrap();
        data.to_string()
    });

    pub static STATE_V01: Lazy<StateV01> = Lazy::new(|| StateV01 {
        typ: StatementVer::V0_1.into(),
        subject: BTreeMap::new(),
        predicate_type: PredicateVer::LinkV0_2,
        predicate: Box::new(PREDICATE_LINK_V02.clone()).into_enum(),
    });

    #[test]
    fn into_trait_equal() {
        let link = StatementWrapper::V0_1(STATE_V01.clone());
        let real = Box::new(STATE_V01.clone()).into_enum();

        assert_eq!(link, real);
    }

    #[test]
    fn create_statement_from_meta() {
        let link = StatementWrapper::from_meta(
            BLANK_META.clone(),
            Some(Box::new(PREDICATE_LINK_V02.clone())),
            StatementVer::V0_1,
        );
        let real = Box::new(STATE_V01.clone()).into_enum();

        assert_eq!(link, real);
    }

    #[test]
    fn serialize_statement() {
        let state = Box::new(STATE_V01.clone()).into_enum();
        let buf = state.into_trait().to_bytes().unwrap();
        let link_serialized = str::from_utf8(&buf).unwrap();

        assert_eq!(link_serialized, *STR_V01);
    }

    #[test]
    fn deserialize_statement() {
        let value: Value = serde_json::from_str(&STR_V01).unwrap();
        let link = StatementWrapper::from_value(value, StatementVer::V0_1).unwrap();
        let real = Box::new(STATE_V01.clone()).into_enum();

        assert_eq!(link, real);
    }

    #[test]
    fn deserialize_auto() {
        let value: Value = serde_json::from_str(&STR_V01).unwrap();
        let link = StatementWrapper::try_from_value(value).unwrap();
        let real = Box::new(STATE_V01.clone()).into_enum();

        assert_eq!(link, real);
    }

    #[test]
    fn deserialize_dismatch() {
        let value: Value = serde_json::from_str(&STR_V01).unwrap();
        for version in StatementVer::iter() {
            if version == StatementVer::V0_1 {
                continue;
            }
            let state = StatementWrapper::from_value(value.clone(), version);

            assert!(state.is_err());
        }
    }
}
