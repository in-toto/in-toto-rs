use std::collections::BTreeMap;

use serde_derive::{Deserialize, Serialize};

use crate::{
    interchange::{DataInterchange, Json},
    models::{
        Convert, LinkMetadata, PredicateLayout, PredicateVersion, PredicateWrapper,
        TargetDescription, VirtualTargetPath,
    },
    Error,
};

use super::{FromMerge, StateLayout, StateVersion, StateWrapper};
use crate::Result;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(deny_unknown_fields)]
/// Statement `V0_1` means the statement of contains a predicate for SLSA format.
///
/// Can be used together with most predicate.
pub struct StateV01 {
    #[serde(rename = "_type")]
    typ: String,
    subject: BTreeMap<VirtualTargetPath, TargetDescription>,
    #[serde(rename = "predicateType")]
    predicate_type: PredicateVersion,
    predicate: PredicateWrapper,
}

impl FromMerge for StateV01 {
    fn merge(meta: LinkMetadata, predicate: Option<Box<dyn PredicateLayout>>) -> Result<StateV01> {
        if predicate.is_none() {
            return Err(Error::AttestationFormatDismatch(
                StateVersion::V0_1.to_string(),
                "None".to_string(),
            ));
        }
        let p = predicate
            .ok_or_else(|| Error::Programming("match rules failed for StateV01".to_string()))?;
        let version = StateVersion::V0_1.try_into()?;
        Ok(StateV01 {
            typ: version,
            subject: meta.products().clone(),
            predicate_type: p.version(),
            predicate: p.into_enum(),
        })
    }
}

impl StateLayout for StateV01 {
    fn version(&self) -> StateVersion {
        StateVersion::V0_1
    }

    fn into_enum(self: Box<Self>) -> StateWrapper {
        StateWrapper::V0_1(*self)
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        Json::canonicalize(&Json::serialize(self)?)
    }
}

#[cfg(test)]
pub mod test {
    use crate::{
        interchange::{DataInterchange, Json},
        models::{
            predicate::link_v02::test::PREDICATE_LINK_V02,
            state::{StateLayout, StateVersion, StateWrapper},
            test::BLANK_META,
            Convert, PredicateLayout, PredicateVersion,
        },
    };
    use std::collections::BTreeMap;
    use std::str;

    use once_cell::sync::Lazy;
    use serde_json::json;
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
                "command": "",
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
        typ: StateVersion::V0_1.try_into().unwrap(),
        subject: BTreeMap::new(),
        predicate_type: PredicateVersion::LinkV0_2,
        predicate: Box::new(PREDICATE_LINK_V02.clone()).into_enum(),
    });

    #[test]
    fn into_trait_equal() {
        let link = StateWrapper::V0_1(STATE_V01.clone());
        let real = Box::new(STATE_V01.clone()).into_enum();

        assert_eq!(link, real);
    }

    #[test]
    fn create_state_from_meta() {
        let link = StateWrapper::from_meta(
            BLANK_META.clone(),
            Some(Box::new(PREDICATE_LINK_V02.clone())),
            StateVersion::V0_1,
        );
        let real = Box::new(STATE_V01.clone()).into_enum();

        assert_eq!(link, real);
    }

    #[test]
    fn serialize_state() {
        let state = Box::new(STATE_V01.clone()).into_enum();
        let buf = state.into_trait().to_bytes().unwrap();
        let link_serialized = str::from_utf8(&buf).unwrap();

        assert_eq!(link_serialized, *STR_V01);
    }

    #[test]
    fn deserialize_state() {
        let link =
            StateWrapper::from_bytes(STR_V01.as_bytes().to_vec(), StateVersion::V0_1).unwrap();
        let real = Box::new(STATE_V01.clone()).into_enum();

        assert_eq!(link, real);
    }

    #[test]
    fn deserialize_auto() {
        let link = StateWrapper::try_from_bytes(STR_V01.as_bytes().to_vec()).unwrap();
        let real = Box::new(STATE_V01.clone()).into_enum();

        assert_eq!(link, real);
    }

    #[test]
    fn deserialize_dismatch() {
        for version in StateVersion::iter() {
            if version == StateVersion::V0_1 {
                continue;
            }
            let state = StateWrapper::from_bytes(STR_V01.as_bytes().to_vec(), version);

            assert!(state.is_err());
        }
    }
}
