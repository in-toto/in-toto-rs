//! # Artifact Rules
//!
//! Artifact rules are used to connect steps together through their
//! materials or products. When connecting steps together, in-toto
//! allows the project owner to enforce the existence of certain
//! artifacts within a step (e.g., the README can only be created
//! in the create-documentation step) and authorize operations on
//! artifacts (e.g., the compile step can use the materials from
//! the checkout-vcs).
//!
//! # Format of Artifact Rule
//!
//! Format of an Artifact Rule is the following:
//! ```plaintext
//! {MATCH <pattern> [IN <source-path-prefix>] WITH (MATERIALS|PRODUCTS) [IN <destination-path-prefix>] FROM <step> ||
//! CREATE <pattern> ||
//! DELETE <pattern> ||
//! MODIFY <pattern> ||
//! ALLOW <pattern> ||
//! REQUIRE <pattern> ||
//! DISALLOW <pattern>}
//! ```
//!
//! Please refer to [`in-toto v0.9 spec`] for concrete functions
//! for different rules (e.g., `MATCH`, `CREATE`, etc.)
//!
//! ## Instantialize
//!
//! As the format given in [`in-toto v0.9 spec`], rule types include
//! `MATCH`, `CREATE`, `DELETE`, `MODIFY`, `ALLOW`, `REQUIRE` and
//! `DISALLOW`.
//!
//! ### MATCH Rule
//!
//! A `MATCH` rule consists of a `<pattern>`,
//! an `IN <source-path-prefix>` (optional), a `WITH (MATERIALS|PRODUCTS)`
//! (must), an `IN <destination-path-prefix>` (optional) and a `FROM <step>`
//! (must).
//!
//! We can build a MATCH rule like this
//! ```
//! # use in_toto::{models::rule::{ArtifactRule, Artifact}, Result};
//!
//! # fn main() -> Result<()> {
//!     let _match_rule = ArtifactRule::Match {
//!         pattern: "pattern/".into(),
//!         in_src: Some("src".into()),
//!         with: Artifact::Materials,
//!         in_dst: Some("dst".into()),
//!         from: "test_step".into(),
//!     };
//!
//!     Ok(())
//! # }
//!
//! ```
//!
//! This rule equals to
//! ```plaintext
//! ["MATCH", "pattern/", "IN", "src", "WITH", "MATERIALS", "IN", "dst", "FROM", "test_step"]
//! ```
//!
//! ### Other Rules
//!
//! The other rules (s.t. `CREATE`, `DELETE`, `MODIFY`, `ALLOW`,
//!  `REQUIRE` and `DISALLOW`) only need one parameter `<pattern>`.
//!
//! For example, we can build a CREATE rule like this
//!
//! ```
//! # use in_toto::{models::rule::ArtifactRule, Result};
//!
//! # fn main() -> Result<()> {
//!     let _create_rule = ArtifactRule::Create("./artifact".into());
//!
//!     Ok(())
//! # }
//!
//! ```
//!
//! This rule equals to
//! ```plaintext
//! ["CREATE", "./artifact"]
//! ```
//!
//! ## Deserialize and Serialize
//!
//! To make it easy to parse `.layout` files, format in [`in-toto v0.9 spec`]
//! is supported when a `.layout` file is being deserialized.
//!
//! For example
//!
//! ```
//! # use serde_json::Error;
//! # use in_toto::models::rule::ArtifactRule;
//!
//! # fn main() {
//! let rule = ArtifactRule::Create("foo.py".into());
//!
//! let rule_raw = r#"["CREATE", "foo.py"]"#;
//! let rule_parsed: ArtifactRule = serde_json::from_str(rule_raw).unwrap();
//! assert_eq!(rule, rule_parsed);
//! # }
//! ```
//!
//! Also, when being serialized, an Artifact Rule will be converted
//! to the format as [`in-toto v0.9 spec`] gives
//!
//! ```
//! # use serde_json::{Error, json};
//! # use in_toto::models::rule::ArtifactRule;
//!
//! # fn main() {
//! let rule = ArtifactRule::Create("foo.py".into());
//!
//! let rule_value = json!(["CREATE", "foo.py"]);
//! let rule_serialized = serde_json::to_value(&rule).unwrap();
//! assert_eq!(rule_serialized, rule_value);
//! # }
//! ```
//!
//! [`in-toto v0.9 spec`]: https://github.com/in-toto/docs/blob/v0.9/in-toto-spec.md#433-artifact-rules

use std::result::Result as StdResult;

use serde::{
    de::{self, SeqAccess, Unexpected, Visitor},
    ser::{Serialize, SerializeSeq},
    Deserialize,
};

use crate::models::VirtualTargetPath;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Artifact {
    Materials,
    Products,
}

impl AsRef<str> for Artifact {
    fn as_ref(&self) -> &str {
        match self {
            Artifact::Materials => "MATERIALS",
            Artifact::Products => "PRODUCTS",
        }
    }
}

/// Artifact rule enum
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArtifactRule {
    /// indicates that products matched by the pattern must not appear
    /// as materials of this step.
    Create(VirtualTargetPath),
    /// indicates that materials matched by the pattern must not appear
    /// as products of this step.
    Delete(VirtualTargetPath),
    /// indicates that products matched by this pattern must appear as
    /// materials of this step, and their hashes must not be the same.
    Modify(VirtualTargetPath),
    /// indicates that artifacts matched by the pattern are allowed as
    /// materials or products of this step.
    Allow(VirtualTargetPath),
    /// indicates that a pattern must appear as a material or product
    /// of this step.
    Require(VirtualTargetPath),
    /// indicates that artifacts matched by the pattern are not allowed
    /// as materials or products of this step.
    Disallow(VirtualTargetPath),
    /// indicates that the artifacts filtered in using `"in_src/pattern"`
    /// must be matched to a `"MATERIAL"` or `"PRODUCT"` from a destination
    /// step with the "in_dst/pattern" filter.
    Match {
        pattern: VirtualTargetPath,
        in_src: Option<String>,
        with: Artifact,
        in_dst: Option<String>,
        from: String,
    },
}

impl ArtifactRule {
    pub fn pattern(&self) -> &VirtualTargetPath {
        match self {
            ArtifactRule::Create(pattern) => pattern,
            ArtifactRule::Delete(pattern) => pattern,
            ArtifactRule::Modify(pattern) => pattern,
            ArtifactRule::Allow(pattern) => pattern,
            ArtifactRule::Require(pattern) => pattern,
            ArtifactRule::Disallow(pattern) => pattern,
            ArtifactRule::Match { pattern, .. } => pattern,
        }
    }
}

impl Serialize for ArtifactRule {
    fn serialize<S>(&self, serializer: S) -> StdResult<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            ArtifactRule::Create(pattern) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("CREATE")?;
                seq.serialize_element(pattern)?;
                seq.end()
            }
            ArtifactRule::Delete(pattern) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("DELETE")?;
                seq.serialize_element(pattern)?;
                seq.end()
            }
            ArtifactRule::Modify(pattern) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("MODIFY")?;
                seq.serialize_element(pattern)?;
                seq.end()
            }
            ArtifactRule::Allow(pattern) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("ALLOW")?;
                seq.serialize_element(pattern)?;
                seq.end()
            }
            ArtifactRule::Require(pattern) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("REQUIRE")?;
                seq.serialize_element(pattern)?;
                seq.end()
            }
            ArtifactRule::Disallow(pattern) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("DISALLOW")?;
                seq.serialize_element(pattern)?;
                seq.end()
            }
            ArtifactRule::Match {
                pattern,
                in_src,
                with,
                in_dst,
                from,
            } => {
                let mut to_be_serialized = vec!["MATCH", pattern.as_ref()];
                if let Some(src) = in_src {
                    to_be_serialized.append(&mut vec!["IN", src]);
                }
                to_be_serialized.append(&mut vec!["WITH", with.as_ref()]);
                if let Some(dst) = in_dst {
                    to_be_serialized.append(&mut vec!["IN", dst]);
                }
                to_be_serialized.append(&mut vec!["FROM", from]);
                let mut seq =
                    serializer.serialize_seq(Some(to_be_serialized.len()))?;
                for e in to_be_serialized {
                    seq.serialize_element(e)?;
                }
                seq.end()
            }
        }
    }
}

/// Visitor helps to deserialize `ArtifactRule`
struct ArtifactRuleVisitor {}

impl ArtifactRuleVisitor {
    pub fn new() -> Self {
        ArtifactRuleVisitor {}
    }
}

impl<'de> Visitor<'de> for ArtifactRuleVisitor {
    type Value = ArtifactRule;

    fn expecting(
        &self,
        formatter: &mut std::fmt::Formatter,
    ) -> std::fmt::Result {
        formatter.write_str("An Artifact Rule for in-toto")
    }

    /// Deserialize a sequence to an `ArtifactRule`.
    fn visit_seq<V>(self, mut seq: V) -> StdResult<ArtifactRule, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let mut len = 0;
        let typ: &str = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(len, &self))?;
        len += 1;

        let pattern: VirtualTargetPath = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(len, &self))?;
        len += 1;

        match typ {
            "CREATE" => Ok(ArtifactRule::Create(pattern)),
            "DELETE" => Ok(ArtifactRule::Delete(pattern)),
            "MODIFY" => Ok(ArtifactRule::Modify(pattern)),
            "ALLOW" => Ok(ArtifactRule::Allow(pattern)),
            "REQUIRE" => Ok(ArtifactRule::Require(pattern)),
            "DISALLOW" => Ok(ArtifactRule::Disallow(pattern)),
            "MATCH" => {
                let in_or_with: String = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(len, &self))?;
                len += 1;

                let mut in_src = None;
                let mut with = Artifact::Materials;
                let mut in_dst = None;

                match &in_or_with[..] {
                    "IN" => {
                        let source_path_prefix: String =
                            seq.next_element()?.ok_or_else(|| {
                                de::Error::invalid_length(len, &self)
                            })?;
                        len += 1;

                        in_src = Some(source_path_prefix);

                        let in_: String =
                            seq.next_element()?.ok_or_else(|| {
                                de::Error::invalid_length(len, &self)
                            })?;
                        len += 1;

                        if in_ != "WITH" {
                            Err(de::Error::invalid_value(
                                Unexpected::Str(&in_),
                                &"IN",
                            ))?
                        }
                    }
                    "WITH" => {}
                    _ => {
                        return Err(de::Error::invalid_value(
                            Unexpected::Str(&in_or_with),
                            &"WITH or IN",
                        ))
                    }
                }

                let target: String = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(len, &self))?;
                len += 1;

                match &target[..] {
                    "MATERIALS" => {}
                    "PRODUCTS" => with = Artifact::Products,
                    _ => Err(de::Error::invalid_value(
                        Unexpected::Str(&target),
                        &"MATERIALS or PRODUCTS",
                    ))?,
                };

                let in_or_from: String = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(len, &self))?;
                len += 1;

                match &in_or_from[..] {
                    "IN" => {
                        let destination_path_prefix: String =
                            seq.next_element()?.ok_or_else(|| {
                                de::Error::invalid_length(len, &self)
                            })?;
                        len += 1;
                        in_dst = Some(destination_path_prefix);

                        let from_: String =
                            seq.next_element()?.ok_or_else(|| {
                                de::Error::invalid_length(len, &self)
                            })?;
                        len += 1;

                        if from_ != "FROM" {
                            return Err(de::Error::invalid_value(
                                Unexpected::Str(&from_),
                                &"FROM",
                            ));
                        }
                    }
                    "FROM" => {}
                    _ => {
                        return Err(de::Error::invalid_value(
                            Unexpected::Str(&in_or_from),
                            &"IN or FROM",
                        ));
                    }
                };

                let from: String = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(len, &self))?;

                Ok(ArtifactRule::Match {
                    pattern,
                    in_src,
                    with,
                    in_dst,
                    from,
                })
            }
            others => {
                Err(de::Error::custom(format!("Unexpected token {}", others)))
            }
        }
    }
}

impl<'de> Deserialize<'de> for ArtifactRule {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "ArtifactRule",
            &["inner"],
            ArtifactRuleVisitor::new(),
        )
    }
}

#[cfg(test)]
pub mod test {
    use rstest::rstest;
    use serde_json::json;

    use super::{Artifact, ArtifactRule};

    /// generate a ARTIFACT_RULE as json:
    /// `[
    ///     "MATCH",
    ///     "pattern/",
    ///     "IN",
    ///     "src",
    ///     "WITH",
    ///     "MATERIALS",
    ///     "IN",
    ///     "dst",
    ///     "FROM",
    ///     "test_step"
    /// ]`
    pub fn generate_materials_rule() -> ArtifactRule {
        ArtifactRule::Match {
            pattern: "pattern/".into(),
            in_src: Some("src".into()),
            with: Artifact::Materials,
            in_dst: Some("dst".into()),
            from: "test_step".into(),
        }
    }

    /// generate a ARTIFACT_RULE as json:
    /// `[
    ///     "MATCH",
    ///     "pattern/",
    ///     "IN",
    ///     "src",
    ///     "WITH",
    ///     "PRODUCTS",
    ///     "IN",
    ///     "dst",
    ///     "FROM",
    ///     "test_step"
    /// ]`
    pub fn generate_products_rule() -> ArtifactRule {
        ArtifactRule::Match {
            pattern: "pattern/".into(),
            in_src: Some("src".into()),
            with: Artifact::Products,
            in_dst: Some("dst".into()),
            from: "test_step".into(),
        }
    }

    #[test]
    fn serialize_match_full() {
        let rule = generate_materials_rule();
        let json = json!([
            "MATCH",
            "pattern/",
            "IN",
            "src",
            "WITH",
            "MATERIALS",
            "IN",
            "dst",
            "FROM",
            "test_step"
        ]);

        let json_serialize = serde_json::to_value(&rule).unwrap();
        assert_eq!(
            json, json_serialize,
            "{:#?} != {:#?}",
            json, json_serialize
        );
    }

    #[test]
    fn serialize_match_without_source() {
        let rule = ArtifactRule::Match {
            pattern: "./".into(),
            in_src: None,
            with: Artifact::Materials,
            in_dst: Some("dst".into()),
            from: "build".into(),
        };

        let json = json!([
            "MATCH",
            "./",
            "WITH",
            "MATERIALS",
            "IN",
            "dst",
            "FROM",
            "build"
        ]);

        let json_serialize = serde_json::to_value(&rule).unwrap();
        assert_eq!(json, json_serialize);
    }

    #[test]
    fn serialize_match_without_dest() {
        let rule = ArtifactRule::Match {
            pattern: "./".into(),
            in_src: Some("pre".into()),
            with: Artifact::Materials,
            in_dst: None,
            from: "build".into(),
        };

        let json = json!([
            "MATCH",
            "./",
            "IN",
            "pre",
            "WITH",
            "MATERIALS",
            "FROM",
            "build"
        ]);

        let json_serialize = serde_json::to_value(&rule).unwrap();
        assert_eq!(
            json, json_serialize,
            "{:#?} != {:#?}",
            json, json_serialize
        );
    }

    #[rstest]
    #[case(ArtifactRule::Create("./artifact".into()), json!(["CREATE", "./artifact"]))]
    #[case(ArtifactRule::Delete("./artifact".into()), json!(["DELETE", "./artifact"]))]
    #[case(ArtifactRule::Modify("./artifact".into()), json!(["MODIFY", "./artifact"]))]
    #[case(ArtifactRule::Allow("./artifact".into()), json!(["ALLOW", "./artifact"]))]
    #[case(ArtifactRule::Require("./artifact".into()), json!(["REQUIRE", "./artifact"]))]
    #[case(ArtifactRule::Disallow("./artifact".into()), json!(["DISALLOW", "./artifact"]))]
    fn serialize_tests(
        #[case] rule: ArtifactRule,
        #[case] json: serde_json::Value,
    ) {
        let json_serialize = serde_json::to_value(&rule).unwrap();
        assert_eq!(
            json, json_serialize,
            "{:#?} != {:#?}",
            json, json_serialize
        );
    }

    #[test]
    fn deserialize_full() {
        let json = r#"[
            "MATCH",
            "pattern/",
            "IN",
            "src",
            "WITH",
            "MATERIALS",
            "IN",
            "dst",
            "FROM",
            "test_step"
        ]"#;
        let rule = generate_materials_rule();

        let rule_parsed: ArtifactRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule, rule_parsed);
    }

    #[test]
    fn deserialize_match_without_source() {
        let json = r#"[
            "MATCH",
            "foo.tar.gz",
            "WITH",
            "PRODUCTS",
            "IN",
            "./dst",
            "FROM",
            "package"
        ]"#;
        let rule = ArtifactRule::Match {
            pattern: "foo.tar.gz".into(),
            in_src: None,
            with: Artifact::Products,
            in_dst: Some("./dst".into()),
            from: "package".into(),
        };

        let rule_parsed: ArtifactRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule, rule_parsed);
    }

    #[test]
    fn deserialize_without_dst() {
        let json = r#"[
            "MATCH",
            "foo.tar.gz",
            "IN",
            "./src",
            "WITH",
            "PRODUCTS",
            "FROM",
            "package"
        ]"#;
        let rule = ArtifactRule::Match {
            pattern: "foo.tar.gz".into(),
            in_src: Some("./src".into()),
            with: Artifact::Products,
            in_dst: None,
            from: "package".into(),
        };

        let rule_parsed: ArtifactRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule, rule_parsed);
    }

    #[rstest]
    #[case(ArtifactRule::Create("./artifact".into()), r#"["CREATE", "./artifact"]"#)]
    #[case(ArtifactRule::Delete("./artifact".into()), r#"["DELETE", "./artifact"]"#)]
    #[case(ArtifactRule::Modify("./artifact".into()), r#"["MODIFY", "./artifact"]"#)]
    #[case(ArtifactRule::Allow("./artifact".into()), r#"["ALLOW", "./artifact"]"#)]
    #[case(ArtifactRule::Require("./artifact".into()), r#"["REQUIRE", "./artifact"]"#)]
    #[case(ArtifactRule::Disallow("./artifact".into()), r#"["DISALLOW", "./artifact"]"#)]
    fn deserialize_tests(#[case] rule: ArtifactRule, #[case] json: &str) {
        let rule_parsed: ArtifactRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule, rule_parsed);
    }
}
