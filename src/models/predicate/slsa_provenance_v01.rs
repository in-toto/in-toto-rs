use std::collections::HashMap;

use chrono::{DateTime, FixedOffset, SecondsFormat};
use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use serde::ser::{Serialize, Serializer};
use serde_derive::{Deserialize, Serialize};

use super::{PredicateLayout, PredicateVersion, PredicateWrapper};
use crate::interchange::{DataInterchange, Json};
use crate::Result;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TimeStamp(pub DateTime<FixedOffset>);

impl Serialize for TimeStamp {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let form = self.0.to_rfc3339_opts(SecondsFormat::Secs, true);
        form.serialize(ser)
    }
}

impl<'de> Deserialize<'de> for TimeStamp {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let form: &str = Deserialize::deserialize(de)?;
        DateTime::parse_from_rfc3339(form)
            .map(TimeStamp)
            .map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct TypeURI(pub String);

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct Builder {
    pub id: TypeURI,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct Completeness {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub materials: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct Recipe {
    #[serde(rename = "type")]
    pub typ: TypeURI,
    #[serde(rename = "definedInMaterial")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defined_in_material: Option<usize>,
    #[serde(rename = "entryPoint")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_point: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    #[serde(rename = "buildInvocationId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_invocation_id: Option<String>,
    #[serde(rename = "buildStartedOn")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_started_on: Option<TimeStamp>,
    #[serde(rename = "buildFinishedOn")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_finished_on: Option<TimeStamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completeness: Option<Completeness>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reproducible: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct Material {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) uri: Option<TypeURI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) digest: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
/// Predicate `SLSAProvenanceV01` means the predicate of SLSA format.
///
/// [SLSAProvenanceV01](https://slsa.dev/provenance/v0.1)
/// can be used together with most states.
pub struct SLSAProvenanceV01 {
    builder: Builder,
    #[serde(skip_serializing_if = "Option::is_none")]
    recipe: Option<Recipe>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Metadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    materials: Option<Vec<Material>>,
}

impl PredicateLayout for SLSAProvenanceV01 {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Json::canonicalize(&Json::serialize(self)?)
    }

    fn into_enum(self: Box<Self>) -> PredicateWrapper {
        PredicateWrapper::SLSAProvenanceV0_1(*self)
    }

    fn version(&self) -> PredicateVersion {
        PredicateVersion::SLSAProvenanceV0_1
    }
}

#[cfg(test)]
pub mod test {
    use std::{collections::HashMap, str};

    use chrono::DateTime;
    use once_cell::sync::Lazy;
    use serde_json::json;
    use strum::IntoEnumIterator;

    use super::{
        Builder, Completeness, Material, Metadata, Recipe, SLSAProvenanceV01, TimeStamp, TypeURI,
    };
    use crate::{
        interchange::{DataInterchange, Json},
        models::{PredicateLayout, PredicateVersion, PredicateWrapper},
    };

    pub static STR_PREDICATE_PROVEN_V01: Lazy<String> = Lazy::new(|| {
        let raw_data = json!({
            "builder": {
                "id": "https://github.com/Attestations/GitHubHostedActions@v1"
            },
            "recipe": {
                "type": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
                "definedInMaterial": 0,
                "entryPoint": "build.yaml:maketgz"
            },
            "metadata": {
                "buildStartedOn": "2020-08-19T08:38:00Z",
                "completeness": {
                    "environment": true
                }
            },
            "materials": [{
                "uri": "git+https://github.com/curl/curl-docker@master",
                "digest": {
                    "sha1": "d6525c840a62b398424a78d792f457477135d0cf"
                }
            }, {
                "uri": "github_hosted_vm:ubuntu-18.04:20210123.1"
            }]
        });
        let value = serde_json::value::to_value(raw_data).unwrap();
        let bytes = Json::canonicalize(&value).unwrap();
        let data = str::from_utf8(&bytes).unwrap();
        data.to_string()
    });

    pub static PREDICATE_PROVEN_V01: Lazy<SLSAProvenanceV01> = Lazy::new(|| {
        let build_started_on = DateTime::parse_from_rfc3339("2020-08-19T08:38:00Z").unwrap();
        SLSAProvenanceV01 {
            builder: Builder {
                id: TypeURI("https://github.com/Attestations/GitHubHostedActions@v1".to_string()),
            },
            recipe: Some(Recipe {
                typ: TypeURI(
                    "https://github.com/Attestations/GitHubActionsWorkflow@v1".to_string(),
                ),
                defined_in_material: Some(0),
                entry_point: Some("build.yaml:maketgz".to_string()),
                arguments: None,
                environment: None,
            }),
            metadata: Some(Metadata {
                build_invocation_id: None,
                build_started_on: Some(TimeStamp(build_started_on)),
                build_finished_on: None,
                completeness: Some(Completeness {
                    arguments: None,
                    environment: Some(true),
                    materials: None,
                }),
                reproducible: None,
            }),
            materials: Some(vec![
                Material {
                    uri: Some(TypeURI(
                        "git+https://github.com/curl/curl-docker@master".to_string(),
                    )),
                    digest: Some(HashMap::from([(
                        "sha1".to_string(),
                        "d6525c840a62b398424a78d792f457477135d0cf".to_string(),
                    )])),
                },
                Material {
                    uri: Some(TypeURI(
                        "github_hosted_vm:ubuntu-18.04:20210123.1".to_string(),
                    )),
                    digest: None,
                },
            ]),
        }
    });

    #[test]
    fn into_trait_equal() {
        let predicate = PredicateWrapper::SLSAProvenanceV0_1(PREDICATE_PROVEN_V01.clone());
        let real = Box::new(PREDICATE_PROVEN_V01.clone()).into_enum();

        assert_eq!(predicate, real);
    }

    #[test]
    fn create_predicate_from_meta() {
        // TODO: convert from metadata is no supported recentely
    }

    #[test]
    fn serialize_predicate() {
        let predicate = Box::new(PREDICATE_PROVEN_V01.clone()).into_enum();
        let buf = predicate.into_trait().to_bytes().unwrap();
        let predicate_serialized = str::from_utf8(&buf).unwrap();

        assert_eq!(predicate_serialized, *STR_PREDICATE_PROVEN_V01);
    }

    #[test]
    fn deserialize_predicate() {
        let predicate = PredicateWrapper::from_bytes(
            STR_PREDICATE_PROVEN_V01.as_bytes(),
            PredicateVersion::SLSAProvenanceV0_1,
        )
        .unwrap();
        let real = Box::new(PREDICATE_PROVEN_V01.clone()).into_enum();

        assert_eq!(predicate, real);
    }

    #[test]
    fn deserialize_auto() {
        let predicate =
            PredicateWrapper::try_from_bytes(STR_PREDICATE_PROVEN_V01.as_bytes()).unwrap();
        let real = Box::new(PREDICATE_PROVEN_V01.clone()).into_enum();

        assert_eq!(predicate, real);
    }

    #[test]
    fn deserialize_dismatch() {
        for version in PredicateVersion::iter() {
            if version == PredicateVersion::SLSAProvenanceV0_1 {
                continue;
            }
            let predicate =
                PredicateWrapper::from_bytes(STR_PREDICATE_PROVEN_V01.as_bytes(), version);

            assert!(predicate.is_err());
        }
    }
}
