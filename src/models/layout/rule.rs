use std::collections::HashMap;
use std::result::Result as StdResult;

use lazy_static::lazy_static;
use serde::{
    de::{self, SeqAccess, Unexpected, Visitor},
    ser::{Serialize, SerializeSeq},
    Deserialize,
};

use crate::{Error, Result};

// keys for ARTIFACT_RULE's inner map
static TYPE: &str = "type";
static PATTERN: &str = "pattern";
static SOURCE_PATH_PREFIX: &str = "source-path-prefix";
static TARGET: &str = "target";
static DESTINATION_PATH_PREFIX: &str = "destination-path-prefix";
static STEP: &str = "step";

// const strings for Rules
static MATERIALS: &str = "MATERIALS";
static PRODUCTS: &str = "PRODUCTS";
static IN: &str = "IN";
static WITH: &str = "WITH";
static FROM: &str = "FROM";

// Rule types
lazy_static! {
    static ref RULE_TYPES: Vec<String> = vec![
        "MATCH".into(),
        "CREATE".into(),
        "DELETE".into(),
        "MODIFY".into(),
        "ALLOW".into(),
        "REQUIRE".into(),
        "DISALLOW".into()
    ];
}

/// Helper to build an ArtifactRule as in-toto spec v0.9
pub struct ArtifactRuleBuilder {
    inner: HashMap<String, String>,
}

impl Default for ArtifactRuleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactRuleBuilder {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Set Rule type for the rule.
    /// Can be one of `MATCH`, `CREATE`, `DELETE`
    /// `MODIFY`, `ALLOW`, `REQUIRE` or `DISALLOW`
    pub fn rule(mut self, typ: &str) -> Self {
        self.inner.insert(TYPE.to_owned(), typ.to_owned());
        self
    }

    /// Set `<pattern>` for the rule.
    pub fn pattern(mut self, pattern: &str) -> Self {
        self.inner.insert(PATTERN.to_owned(), pattern.to_owned());
        self
    }

    /// Set `<source-path-prefix>` for the rule.
    /// Only works for `MATCH` rule
    pub fn in_source_path_prefix(mut self, source_path_prefix: &str) -> Self {
        self.inner
            .insert(SOURCE_PATH_PREFIX.to_owned(), source_path_prefix.to_owned());
        self
    }

    /// Set `<destination-path-prefix>` for the rule.
    /// Only works for `MATCH` rule
    pub fn in_destination_path_prefix(mut self, destination_path_prefix: &str) -> Self {
        self.inner.insert(
            DESTINATION_PATH_PREFIX.to_owned(),
            destination_path_prefix.to_owned(),
        );
        self
    }

    /// Set thr rule's check target is `MATERIALS`.
    /// Only works for `MATCH` rule
    pub fn with_materials(mut self) -> Self {
        self.inner.insert(TARGET.to_owned(), MATERIALS.to_owned());
        self
    }

    /// Set thr rule's check target is `PRODUCTS`.
    /// Only works for `MATCH` rule
    pub fn with_products(mut self) -> Self {
        self.inner.insert(TARGET.to_owned(), PRODUCTS.to_owned());
        self
    }

    /// Set `<step>` for the rule.
    /// Only works for `MATCH` rule
    pub fn from_step(mut self, step: &str) -> Self {
        self.inner.insert(STEP.to_owned(), step.to_owned());
        self
    }

    /// Check the parameters input for the Builder and
    /// build ArtifactRule
    pub fn build(self) -> Result<ArtifactRule> {
        let typ = self
            .inner
            .get(TYPE)
            .ok_or_else(|| Error::Programming("ArtifactRule should have type".into()))?
            .to_owned();

        // Check whether type is allowed
        if !RULE_TYPES.contains(&typ) {
            return Err(Error::Programming(
                r"ArtifactRule's type should be one of :
            `MATCH`, 'CREATE', 'DELETE', 'MODIFY', 'ALLOW', 'REQUIRE' or 'DISALLOW'"
                    .into(),
            ));
        }

        if !self.inner.contains_key(PATTERN) {
            return Err(Error::Programming(
                "ArtifactRule should have a <pattern> field".into(),
            ));
        }

        if &typ[..] == "MATCH" {
            if !self.inner.contains_key(STEP) {
                return Err(Error::Programming(
                    "A match rule should have a <step> field".into(),
                ));
            }

            if !self.inner.contains_key(TARGET) {
                return Err(Error::Programming(
                    "A match rule should be either MATERIALS or PRODUCTS".into(),
                ));
            }
        }

        Ok(ArtifactRule { inner: self.inner })
    }
}

/// ARTIFACT_RULE in section 4.3.3 of in-toto spec v0.9
/// # Instantiation and Deserialization
/// ```no_run
/// # use serde_json::Error;
/// # use in_toto::models::rule::{ArtifactRule, ArtifactRuleBuilder};
///
/// # fn main() {
/// let rule = ArtifactRuleBuilder::new()
///     .rule("CREATE")
///     .pattern("foo.py")
///     .build()
///     .unwrap();
///
/// let rule_raw = r#"[["CREATE"], ["foo.py"]]"#;
/// let rule_parsed: ArtifactRule = serde_json::from_str(rule_raw).unwrap();
/// assert_eq!(rule, rule_parsed);
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct ArtifactRule {
    inner: HashMap<String, String>,
}

impl ArtifactRule {}

impl Serialize for ArtifactRule {
    fn serialize<S>(&self, serializer: S) -> StdResult<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let typ = self.inner.get(TYPE).unwrap().to_owned();
        // here use unwrap() because when an ArtifactRule is
        // successfully built from ArtifactRuleBuilder, the key 'TYPE' is
        // ensured to exist in the inner map.
        let pattern = self.inner.get(PATTERN).unwrap().to_owned();
        let mut statement = vec![typ.clone(), pattern];

        if &typ[..] == "MATCH" {
            match self.inner.get(SOURCE_PATH_PREFIX) {
                Some(src) => {
                    statement.push(IN.into());
                    statement.push(src.into());
                }
                None => {}
            }

            let target = self.inner.get(TARGET).unwrap().to_owned();
            statement.push(WITH.into());
            statement.push(target);

            match self.inner.get(DESTINATION_PATH_PREFIX) {
                Some(dst) => {
                    statement.push("IN".into());
                    statement.push(dst.into());
                }
                None => {}
            }

            let step = self.inner.get(STEP).unwrap().to_owned();
            statement.push(FROM.into());
            statement.push(step);
        }

        let len = Some(statement.len());

        let mut seq = serializer.serialize_seq(len)?;
        for e in statement {
            seq.serialize_element(&e)?;
        }
        seq.end()
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

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("An Artifact Rule for in-toto")
    }

    /// Deserialize a sequence to an `ArtifactRule`.
    fn visit_seq<V>(self, mut seq: V) -> StdResult<ArtifactRule, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let mut len = 0;
        let typ: String = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(len, &self))?;
        len += 1;

        let pattern: String = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(len, &self))?;
        len += 1;
        let mut builder = ArtifactRuleBuilder::new().rule(&typ).pattern(&pattern);

        if &typ[..] == "MATCH" {
            let in_or_with: String = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(len, &self))?;
            len += 1;

            match &in_or_with[..] {
                "IN" => {
                    let source_path_prefix: String = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(len, &self))?;
                    len += 1;
                    builder = builder.in_source_path_prefix(&source_path_prefix);

                    let in_: String = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(len, &self))?;
                    len += 1;

                    if in_ != WITH {
                        Err(de::Error::invalid_value(Unexpected::Str(&in_), &"IN"))?
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
                "MATERIALS" => builder = builder.with_materials(),
                "PRODUCTS" => builder = builder.with_products(),
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
                    let destination_path_prefix: String = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(len, &self))?;
                    len += 1;
                    builder = builder.in_destination_path_prefix(&destination_path_prefix);

                    let from_: String = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(len, &self))?;
                    len += 1;

                    if from_ != FROM {
                        return Err(de::Error::invalid_value(Unexpected::Str(&from_), &"FROM"));
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

            let step: String = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(len, &self))?;

            builder = builder.from_step(&step);
        }

        match builder.build() {
            Ok(rule) => Ok(rule),
            Err(e) => Err(de::Error::custom(e.to_string())),
        }
    }
}

impl<'de> Deserialize<'de> for ArtifactRule {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct("ArtifactRule", &["inner"], ArtifactRuleVisitor::new())
    }
}

#[cfg(test)]
pub mod test {
    use serde_json::json;

    use super::{ArtifactRule, ArtifactRuleBuilder};

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
        ArtifactRuleBuilder::new()
            .rule("MATCH")
            .pattern("pattern/")
            .in_source_path_prefix("src")
            .with_materials()
            .in_destination_path_prefix("dst")
            .from_step("test_step")
            .build()
            .unwrap()
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
        ArtifactRuleBuilder::new()
            .rule("MATCH")
            .pattern("pattern/")
            .in_source_path_prefix("src")
            .with_products()
            .in_destination_path_prefix("dst")
            .from_step("test_step")
            .build()
            .unwrap()
    }

    #[test]
    fn success_build_rule() {
        let res = ArtifactRuleBuilder::new()
            .rule("MATCH")
            .pattern("a.out")
            .in_source_path_prefix("./src")
            .with_materials()
            .in_destination_path_prefix("./dst")
            .from_step("build")
            .build();
        assert!(res.is_ok());
    }

    #[test]
    fn fail_build_rule() {
        let res = ArtifactRuleBuilder::new()
            .rule("MATCH")
            .in_source_path_prefix("./src")
            .with_materials()
            .in_destination_path_prefix("./dst")
            .from_step("build")
            .build();
        // No pattern here is illegal
        assert!(res.is_err());
    }

    #[test]
    fn serialize_match_full() {
        let rule = ArtifactRuleBuilder::new()
            .rule("MATCH")
            .pattern("./")
            .in_source_path_prefix("pre")
            .with_materials()
            .in_destination_path_prefix("dst")
            .from_step("build")
            .build()
            .unwrap();

        let json = json!([
            "MATCH",
            "./",
            "IN",
            "pre",
            "WITH",
            "MATERIALS",
            "IN",
            "dst",
            "FROM",
            "build"
        ]);

        let json_serialize = serde_json::to_value(&rule).unwrap();
        assert_eq!(json, json_serialize, "{:#?} != {:#?}", json, json_serialize);
    }

    #[test]
    fn serialize_match_without_source() {
        let rule = ArtifactRuleBuilder::new()
            .rule("MATCH")
            .pattern("./")
            .with_materials()
            .in_destination_path_prefix("dst")
            .from_step("build")
            .build()
            .unwrap();

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
        let rule = ArtifactRuleBuilder::new()
            .rule("MATCH")
            .pattern("./")
            .in_source_path_prefix("pre")
            .with_materials()
            .from_step("build")
            .build()
            .unwrap();

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
        assert_eq!(json, json_serialize, "{:#?} != {:#?}", json, json_serialize);
    }

    #[test]
    fn serialize_other() {
        let rule = ArtifactRuleBuilder::new()
            .rule("CREATE")
            .pattern("./artifact")
            .build()
            .unwrap();

        let json = json!(["CREATE", "./artifact"]);
        let json_serialize = serde_json::to_value(&rule).unwrap();
        assert_eq!(json, json_serialize, "{:#?} != {:#?}", json, json_serialize);
    }

    #[test]
    fn deserialize_full() {
        let json = r#"[
            "MATCH",
            "foo.tar.gz",
            "IN",
            "./src",
            "WITH",
            "PRODUCTS",
            "IN",
            "./dst",
            "FROM",
            "package"
        ]"#;
        let rule = ArtifactRuleBuilder::new()
            .rule("MATCH")
            .pattern("foo.tar.gz")
            .in_source_path_prefix("./src")
            .with_products()
            .in_destination_path_prefix("./dst")
            .from_step("package")
            .build()
            .unwrap();

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
        let rule = ArtifactRuleBuilder::new()
            .rule("MATCH")
            .pattern("foo.tar.gz")
            .with_products()
            .in_destination_path_prefix("./dst")
            .from_step("package")
            .build()
            .unwrap();

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
        let rule = ArtifactRuleBuilder::new()
            .rule("MATCH")
            .pattern("foo.tar.gz")
            .in_source_path_prefix("./src")
            .with_products()
            .from_step("package")
            .build()
            .unwrap();

        let rule_parsed: ArtifactRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule, rule_parsed);
    }

    #[test]
    fn deserialize_other() {
        let json = r#"[
            "DELETE",
            "foo.pyc"
        ]"#;
        let rule = ArtifactRuleBuilder::new()
            .rule("DELETE")
            .pattern("foo.pyc")
            .build()
            .unwrap();

        let rule_parsed: ArtifactRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule, rule_parsed);
    }
}
