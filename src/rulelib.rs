//! Helper for ArtifactRule to apply on LinkMetadata

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

use log::warn;

use crate::models::rule::Artifact;
use crate::models::supply_chain_item::SupplyChainItem;
use crate::models::{rule::ArtifactRule, LinkMetadata};
use crate::models::{TargetDescription, VirtualTargetPath};
use crate::{Error, Result};

/// Canonicalize a given [`VirtualTargetPath`]. For example
/// `/test/1/2/../3` -> `/test/1/3`. If any error
/// occurs, just warn it and return None.
fn canonicalize_path(path: &VirtualTargetPath) -> Option<VirtualTargetPath> {
    let path = path_clean::clean(path.value());
    VirtualTargetPath::new(path.into_os_string().into_string().unwrap()).ok()
}

/// Apply match rule. The parameters:
/// * `rule`: MATCH rule to be applied (if not a MATCH rule, will be paniced)
/// * `src_artifacts`: artifacts of a given link (either Products or Materials)
/// * `src_artifact_queue`: artifact paths (canonicalized) of the same link (either Products or Materials)
/// * `items_metadata`: a <name> to <link> hashmap
/// This function will match the artifact paths of `src_artifact_queue`
/// and the `dst_artifacts`. Here `dst_artifacts` can be calculated
/// by indexing the step name from `items_metadata`. Return value is
/// the matched artifact paths.
fn verify_match_rule(
    rule: &ArtifactRule,
    src_artifacts: &BTreeMap<VirtualTargetPath, TargetDescription>,
    src_artifact_queue: &BTreeSet<VirtualTargetPath>,
    items_metadata: &HashMap<String, LinkMetadata>,
) -> BTreeSet<VirtualTargetPath> {
    let mut consumed = BTreeSet::new();

    match rule {
        ArtifactRule::Match {
            pattern,
            in_src,
            with,
            in_dst,
            from,
        } => {
            let dst_link = match items_metadata.get(from) {
                Some(lm) => lm,
                None => {
                    warn!("no link metadata {} found.", from);
                    return consumed;
                }
            };

            let dst_artifact = match with {
                Artifact::Materials => &dst_link.materials,
                Artifact::Products => &dst_link.products,
            };

            let src_artifacts: BTreeMap<VirtualTargetPath, TargetDescription> = src_artifacts
                .iter()
                .map(|(path, value)| {
                    (
                        canonicalize_path(path).unwrap_or_else(|| path.clone()),
                        value.clone(),
                    )
                })
                .collect();

            let dst_artifacts: BTreeMap<VirtualTargetPath, TargetDescription> = dst_artifact
                .iter()
                .map(|(path, value)| {
                    (
                        canonicalize_path(path).unwrap_or_else(|| path.clone()),
                        value.clone(),
                    )
                })
                .collect();

            let dst_prefix = {
                match in_dst {
                    None => String::new(),
                    Some(dst_dir) => {
                        let mut res = PathBuf::new();
                        res.push(dst_dir);
                        let mut res = res.to_string_lossy().to_string();
                        res.push('/');
                        res
                    }
                }
            };

            let src_prefix = {
                match in_src {
                    None => String::new(),
                    Some(src_dir) => {
                        let mut res = PathBuf::new();
                        res.push(src_dir);
                        let mut res = res.to_string_lossy().to_string();
                        res.push('/');
                        res
                    }
                }
            };

            for src_path in src_artifact_queue {
                let src_base_path = src_path
                    .value()
                    .strip_prefix(&src_prefix)
                    .unwrap_or_else(|| src_path.value());
                let src_base_path = VirtualTargetPath::new(src_base_path.to_string())
                    .expect("Unexpected VirtualTargetPath creation failed");

                if let Err(e) = src_base_path.matches(pattern.value()) {
                    warn!("match failed: {}", e.to_string());
                    continue;
                }

                let dst_path = {
                    let mut res = PathBuf::new();
                    res.push(&dst_prefix);
                    res.push(src_base_path.value());
                    VirtualTargetPath::new(res.to_string_lossy().to_string())
                        .expect("Unexpected VirtualTargetPath creation failed")
                };

                if let Some(dst_artifact) = dst_artifacts.get(&dst_path) {
                    if src_artifacts[src_path] == *dst_artifact {
                        consumed.insert(src_path.clone());
                    }
                }
            }
        }
        _ => panic!("Unexpected rule type"),
    }

    consumed
}

/// Apply rules of the given [`SupplyChainItem`] onto the [`LinkMetadata`]
pub(crate) fn apply_rules_on_link(
    item: &Box<dyn SupplyChainItem>,
    reduced_link_files: &HashMap<String, LinkMetadata>,
) -> Result<()> {
    // name of the given item
    let item_name = item.name();

    // get the LinkMetadata for the given SupplyChainItem (`step` or `inspection`)
    let src_link = reduced_link_files.get(item_name).ok_or_else(|| {
        Error::VerificationFailure(format!("can not find link metadata of step {}", item_name,))
    })?;

    // materials of this link
    let material_paths: BTreeSet<VirtualTargetPath> = src_link
        .materials
        .iter()
        .filter_map(|(path, _)| canonicalize_path(path))
        .collect();

    // products of this link
    let product_paths: BTreeSet<VirtualTargetPath> = src_link
        .products
        .iter()
        .filter_map(|(path, _)| canonicalize_path(path))
        .collect();

    // prepare sets of artifacts for `create`, `delete` and `modify` rules.
    // these are calculated from the link's materials and products
    let created: BTreeSet<_> = product_paths.difference(&material_paths).cloned().collect();
    let deleted: BTreeSet<_> = material_paths.difference(&product_paths).cloned().collect();
    let modified: BTreeSet<_> = material_paths
        .intersection(&product_paths)
        .cloned()
        .filter_map(|name| {
            if src_link.materials[&name] != src_link.products[&name] {
                Some(name)
            } else {
                None
            }
        })
        .collect();

    #[derive(Debug)]
    struct VerificationDataList<'a> {
        src_type: Artifact,
        rules: &'a Vec<ArtifactRule>,
        artifacts: &'a BTreeMap<VirtualTargetPath, TargetDescription>,
        artifact_paths: BTreeSet<VirtualTargetPath>,
    }

    let list = [
        // rule expected materials
        VerificationDataList {
            src_type: Artifact::Materials,
            rules: item.expected_materials(),
            artifacts: &src_link.materials,
            artifact_paths: material_paths,
        },
        // rule expected products
        VerificationDataList {
            src_type: Artifact::Products,
            rules: item.expected_products(),
            artifacts: &src_link.products,
            artifact_paths: product_paths,
        },
    ];

    for verification_data in list {
        // rules to apply onto the link metadata
        let rules = verification_data.rules;
        // artifacts from the link metadata of this step, whose paths are all canonicalized
        let mut queue = verification_data.artifact_paths;
        // artifacts from the link metadata of this step and their digests
        let artifacts = verification_data.artifacts;

        // for every rule, we choose those items whose path matches the given pattern
        // rule in the queue as a set named `filtered`. and use the set to filter
        // items in `queue` using rule CREATE, DELETE, MODIFY, ALLOW, REQUIRE and DISALLOW.
        // besides, use MATCH rule to filter other items.
        for rule in rules {
            let filtered: BTreeSet<_> = queue
                .iter()
                .filter(|p| p.matches(rule.pattern().value()).unwrap_or(false))
                .cloned()
                .collect();
            let consumed = match rule {
                ArtifactRule::Create(_) => filtered.intersection(&created).cloned().collect(),
                ArtifactRule::Delete(_) => filtered.intersection(&deleted).cloned().collect(),
                ArtifactRule::Modify(_) => filtered.intersection(&modified).cloned().collect(),
                ArtifactRule::Allow(_) => filtered,
                ArtifactRule::Require(_) => {
                    if !queue.contains(rule.pattern()) {
                        return Err(Error::ArtifactRuleError(format!(
                            r#"artifact verification failed for {:?} in REQUIRE '{:?}',
                        because {:?} is not in {:?}"#,
                            verification_data.src_type,
                            rule.pattern(),
                            rule.pattern(),
                            queue
                        )));
                    } else {
                        BTreeSet::new()
                    }
                }
                ArtifactRule::Disallow(_) => {
                    if !filtered.is_empty() {
                        return Err(Error::ArtifactRuleError(format!(
                            r#"artifact verification failed for {:?} in DISALLOW, because {:?} is disallowed by rule {:?} in {}"#,
                            verification_data.src_type, filtered, rule, item_name,
                        )));
                    } else {
                        BTreeSet::new()
                    }
                }
                ArtifactRule::Match { .. } => {
                    verify_match_rule(rule, artifacts, &queue, reduced_link_files)
                }
            };

            queue = queue.difference(&consumed).cloned().collect();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    use rstest::rstest;

    use crate::models::VirtualTargetPath;

    #[rstest]
    #[case("test/../1/1/2", "1/1/2")]
    #[case("test/../../1/2", "../1/2")]
    #[case("../././../1/2", "../../1/2")]
    fn canonicalize_path(#[case] given: &str, #[case] expected: &str) {
        let expected =
            Some(VirtualTargetPath::new(expected.to_string()).expect("Unexpected creation failed"));
        let processed =
            VirtualTargetPath::new(given.to_string()).expect("Unexpected creation failed");
        let processed = super::canonicalize_path(&processed);
        assert_eq!(expected, processed);
    }

    #[rstest]
    #[
        case(
            r#"["MATCH", "demo-project.tar.gz", "WITH", "PRODUCTS", "FROM", "package"]"#,
            r#"{"demo-project.tar.gz": {"sha256": "2989659e6836c941e9015bf38af3cb045365520dbf80460d8a44b2c5b6677fd9"}, "not-deleted.tar": {"sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}}"#,
            r#"["demo-project.tar.gz", "not-deleted.tar"]"#,
            r#"{"package":{"_type":"link","byproducts":{"return-value":0,"stderr":"","stdout":"demo-project/\ndemo-project/foo.py\n"},"command":["tar","--exclude",".git","-zcvf","demo-project.tar.gz","demo-project"],"environment":{},"materials":{"demo-project/foo.py":{"sha256":"c2c0ea54fa94fac3a4e1575d6ed3bbd1b01a6d0b8deb39196bdc31c457ef731b"}},"name":"package","products":{"demo-project.tar.gz":{"sha256":"2989659e6836c941e9015bf38af3cb045365520dbf80460d8a44b2c5b6677fd9"}}}}"#,
            r#"["demo-project.tar.gz"]"#,
        )]
    #[
        case(
            r#"["MATCH", "*", "WITH", "PRODUCTS", "IN", "test", "FROM", "package"]"#,
            r#"{"demo-project.tar.gz": {"sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}}"#,
            r#"["demo-project.tar.gz"]"#,
            r#"{"package":{"_type":"link","byproducts":{"return-value":0,"stderr":"","stdout":"demo-project/\ndemo-project/foo.py\n"},"command":["tar","--exclude",".git","-zcvf","demo-project.tar.gz","demo-project"],"environment":{},"materials":{"demo-project/foo.py":{"sha256":"c2c0ea54fa94fac3a4e1575d6ed3bbd1b01a6d0b8deb39196bdc31c457ef731b"}},"name":"package","products":{"test/demo-project.tar.gz":{"sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}}}}"#,
            r#"["demo-project.tar.gz"]"#,
        )
    ]
    #[
        case(
            r#"["MATCH", "test1", "IN", "dir1", "WITH", "PRODUCTS", "IN", "test", "FROM", "package"]"#,
            r#"{"dir1/test1": {"sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}}"#,
            r#"["dir1/test1"]"#,
            r#"{"package":{"_type":"link","byproducts":{},"command":[""],"environment":{},"materials":{},"name":"package","products":{"test/test1":{"sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}}}}"#,
            r#"["dir1/test1"]"#,
        )
    ]
    fn verify_match_rule(
        #[case] rule: &str,
        #[case] src_artifacts: &str,
        #[case] src_artifact_queue: &str,
        #[case] items_metadata: &str,
        #[case] expected: &str,
    ) {
        let rule = serde_json::from_str(rule).expect("Parse artifact rule failed");
        let src_artifacts =
            serde_json::from_str(src_artifacts).expect("Parse Source Artifacts failed");
        let src_artifact_queue =
            serde_json::from_str(src_artifact_queue).expect("Parse Source Artifact Queue failed");
        let items_metadata =
            serde_json::from_str(items_metadata).expect("Parse Metadata HashMap failed");
        let expected = serde_json::from_str(expected).expect("Parse  failed");
        let got =
            super::verify_match_rule(&rule, &src_artifacts, &src_artifact_queue, &items_metadata);
        assert_eq!(got, expected);
    }
}
