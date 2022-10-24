use std::collections::HashMap;

use serde_derive::{Deserialize, Serialize};

use super::slsa_provenance_v01::{Builder, Material, Metadata, TypeURI};
use super::{PredicateLayout, PredicateVersion, PredicateWrapper};
use crate::interchange::{DataInterchange, Json};
use crate::Result;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct ConfigSource {
    pub uri: Option<TypeURI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<HashMap<String, String>>,
    #[serde(rename = "entryPoint")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_point: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    #[serde(rename = "configSource")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_source: Option<ConfigSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
/// Predicate `SLSAProvenanceV02` means the predicate of SLSA format.
///
/// [SLSAProvenanceV02](https://slsa.dev/provenance/v0.2)
/// can be used together with most states.
pub struct SLSAProvenanceV02 {
    pub builder: Builder,
    #[serde(rename = "buildType")]
    pub build_type: TypeURI,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocation: Option<Invocation>,
    #[serde(rename = "buildConfig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_config: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub materials: Option<Vec<Material>>,
}

impl PredicateLayout for SLSAProvenanceV02 {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Json::canonicalize(&Json::serialize(self)?)
    }

    fn into_enum(self: Box<Self>) -> PredicateWrapper {
        PredicateWrapper::SLSAProvenanceV0_2(*self)
    }

    fn version(&self) -> PredicateVersion {
        PredicateVersion::SLSAProvenanceV0_2
    }
}

#[cfg(test)]
pub mod test {
    use std::collections::HashMap;
    use std::str;

    use chrono::DateTime;
    use once_cell::sync::Lazy;
    use serde_json::json;
    use strum::IntoEnumIterator;

    use super::{ConfigSource, Invocation, SLSAProvenanceV02};
    use crate::{
        interchange::{DataInterchange, Json},
        models::{
            predicate::slsa_provenance_v01::{
                Builder, Completeness, Material, Metadata, TimeStamp, TypeURI,
            },
            PredicateLayout, PredicateVersion, PredicateWrapper,
        },
    };

    pub static STR_PREDICATE_PROVEN_V02: Lazy<String> = Lazy::new(|| {
        let raw_data = json!({
            "builder": {
                "id": "https://github.com/Attestations/GitHubHostedActions@v1"
            },
            "buildType": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
            "invocation": {
                "configSource": {
                    "uri": "git+https://github.com/curl/curl-docker@master",
                    "digest": {
                        "sha1": "d6525c840a62b398424a78d792f457477135d0cf"
                    },
                    "entryPoint": "build.yaml:maketgz"
                }
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

    pub static PREDICATE_PROVEN_V02: Lazy<SLSAProvenanceV02> = Lazy::new(|| {
        let build_started_on = DateTime::parse_from_rfc3339("2020-08-19T08:38:00Z").unwrap();
        let digest = HashMap::from([(
            "sha1".to_string(),
            "d6525c840a62b398424a78d792f457477135d0cf".to_string(),
        )]);
        SLSAProvenanceV02 {
            builder: Builder {
                id: TypeURI("https://github.com/Attestations/GitHubHostedActions@v1".to_string()),
            },
            build_type: TypeURI(
                "https://github.com/Attestations/GitHubActionsWorkflow@v1".to_string(),
            ),
            invocation: Some(Invocation {
                config_source: Some(ConfigSource {
                    uri: Some(TypeURI(
                        "git+https://github.com/curl/curl-docker@master".to_string(),
                    )),
                    digest: Some(digest),
                    entry_point: Some("build.yaml:maketgz".to_string()),
                }),
                parameters: None,
                environment: None,
            }),
            build_config: None,
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
        let predicate = PredicateWrapper::SLSAProvenanceV0_2(PREDICATE_PROVEN_V02.clone());
        let real = Box::new(PREDICATE_PROVEN_V02.clone()).into_enum();

        assert_eq!(predicate, real);
    }

    #[test]
    fn create_predicate_from_meta() {
        // TODO: convert from metadata is no supported recentely
    }

    #[test]
    fn serialize_predicate() {
        let predicate = Box::new(PREDICATE_PROVEN_V02.clone()).into_enum();
        let buf = predicate.into_trait().to_bytes().unwrap();
        let predicate_serialized = str::from_utf8(&buf).unwrap();

        assert_eq!(predicate_serialized, *STR_PREDICATE_PROVEN_V02);
    }

    #[test]
    fn deserialize_predicate() {
        let predicate = PredicateWrapper::from_bytes(
            STR_PREDICATE_PROVEN_V02.as_bytes(),
            PredicateVersion::SLSAProvenanceV0_2,
        )
        .unwrap();
        let real = Box::new(PREDICATE_PROVEN_V02.clone()).into_enum();

        assert_eq!(predicate, real);
    }

    #[test]
    fn deserialize_auto() {
        let predicate =
            PredicateWrapper::try_from_bytes(STR_PREDICATE_PROVEN_V02.as_bytes()).unwrap();
        let real = Box::new(PREDICATE_PROVEN_V02.clone()).into_enum();

        assert_eq!(predicate, real);
    }

    #[test]
    fn deserialize_dismatch() {
        for version in PredicateVersion::iter() {
            if version == PredicateVersion::SLSAProvenanceV0_2 {
                continue;
            }
            let predicate =
                PredicateWrapper::from_bytes(STR_PREDICATE_PROVEN_V02.as_bytes(), version);

            assert!(predicate.is_err());
        }
    }
}
