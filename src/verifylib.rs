//! A tool to be used by the client to perform verification on the final product.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use glob::glob;
use log::{debug, info, warn};

use crate::{
    crypto::{KeyId, PublicKey},
    models::{
        step::Step, supply_chain_item::SupplyChainItem, LayoutMetadata, LinkMetadata,
        LinkMetadataBuilder, Metablock, MetadataWrapper,
    },
    rulelib::apply_rules_on_link,
    runlib::in_toto_run,
};
use crate::{Error, Result};

/// verify_layout_signatures can verify the layout wrapped in a Metablock with given
/// set of public keys. If verification fails, an error occurs.
fn verify_layout_signatures(
    layout: &Metablock,
    layout_keys: &HashMap<KeyId, PublicKey>,
) -> Result<MetadataWrapper> {
    layout.verify(layout_keys.len() as u32, layout_keys.values())
}

/// verify_layout_expiration will verify whether the layout has expired
fn verify_layout_expiration(layout: &LayoutMetadata) -> Result<()> {
    let time = layout.expires;
    let now = chrono::Utc::now();
    if time < now {
        return Err(Error::VerificationFailure("layout expired".to_string()));
    }

    Ok(())
}

/// load content from path to a Metablock
fn load_linkfile(path: &PathBuf) -> Result<Metablock> {
    let content = fs::read_to_string(path)?;
    let meta = serde_json::from_str(&content)?;
    Ok(meta)
}

/// Match signer's key id and metablock's signatures, if one of the
/// signatures is signed with the signer's key, insert it into the
/// given links_per_step map.
fn match_signatures(
    link_metablock: Metablock,
    signer_short_key_id: &str,
    links_per_step: &mut HashMap<KeyId, Metablock>,
) {
    for sig in &link_metablock.signatures {
        if sig.key_id().prefix() == signer_short_key_id {
            links_per_step.insert(sig.key_id().clone(), link_metablock);
            break;
        }
    }
}

/// load_links_for_layout will load Metablock from disk,
/// return a map containing the Metablocks.
/// The returned value is a nested HashMap
/// * step-name => (key-id => Metablock)
fn load_links_for_layout(
    layout: &LayoutMetadata,
    link_dir: &str,
) -> Result<HashMap<String, HashMap<KeyId, Metablock>>> {
    let mut steps_links_metadata = HashMap::new();

    for step in &layout.steps {
        let mut links_per_step = HashMap::new();

        let pattern = format!("{}.????????.link", step.name);
        let mut path_pattern = PathBuf::from(link_dir);
        path_pattern.push(pattern);
        let path_pattern = path_pattern.to_str().ok_or_else(|| {
            Error::VerificationFailure(format!("Pathbuf convert to str failed: {:?}", path_pattern))
        })?;
        let matched_files = glob(path_pattern)
            .map_err(|e| Error::VerificationFailure(format!("Path glob error: {}", e)))?;
        for link_path in matched_files.flatten() {
            // load link from the disk, canbe either a linkfile or a layout file
            let link_metablock = load_linkfile(&link_path)?;

            // Get the key-id that signed this link file
            let signer_short_key_id = link_path
                .file_name()
                .ok_or_else(|| Error::VerificationFailure("link_file name get failed.".into()))?
                .to_str()
                .ok_or_else(|| Error::VerificationFailure("link_file name get failed.".into()))?
                .to_string();

            // by trim filename's start <step-name>." and end ".link"
            let signer_short_key_id = signer_short_key_id
                .trim_end_matches(".link")
                .trim_start_matches(&step.name)
                .trim_start_matches('.');

            match_signatures(link_metablock, signer_short_key_id, &mut links_per_step);
        }

        let lins_per_step_len = links_per_step.len();
        if lins_per_step_len < step.threshold as usize {
            return Err(Error::VerificationFailure(format!(
                "Step {} requires {} link metadata file(s), found {}",
                step.name, step.threshold, lins_per_step_len
            )));
        } else {
            steps_links_metadata.insert(step.name.clone(), links_per_step);
        }
    }

    Ok(steps_links_metadata)
}

/// Verify given step's links' signature, and checkout whether
/// at least "threshold" signatures are validated. Returns
/// validated metadata.
fn verify_link_signature_thresholds_step(
    step: &Step,
    links: &HashMap<KeyId, Metablock>,
    pubkeys: &HashMap<KeyId, PublicKey>,
) -> Result<HashMap<KeyId, Metablock>> {
    let mut metablocks = HashMap::new();

    // Get all links for the given step, verify them, and record the good
    // links in the HashMap.
    for (signer_key_id, link_metablock) in links {
        // For each link corresponding to a step, check that the signer key was
        // authorized by checking whether it's included in the layout.
        // Only good links are stored, to verify thresholds.
        // The sign key of the link is not authorized in the layout
        if let Some(authorized_key) = pubkeys.get(signer_key_id) {
            let authorized_key = vec![authorized_key];
            if link_metablock.verify(1, authorized_key).is_ok() {
                metablocks.insert(signer_key_id.clone(), link_metablock.clone());
            }
        }
        // in-toto v0.9's signature doesn't have a cert field,
        // thus no cert relative operations will be performed.
    }

    if metablocks.len() < step.threshold as usize {
        return Err(Error::VerificationFailure(
            format!(
                "step '{}' requires {} link metadata file(s). {} out of {} available link(s) have a valid signature from an authorized signer",
                step.name,
                step.threshold,
                metablocks.len(),
                links.len(),
            )
        ));
    }

    Ok(metablocks)
}

/// verify_link_signature_thresholds will verify links' signature
/// and check whether link file number meets each step's threshold.
/// Returns only validated link files.
fn verify_link_signature_thresholds(
    layout: &LayoutMetadata,
    steps_links_metadata: HashMap<String, HashMap<KeyId, Metablock>>,
) -> Result<HashMap<String, HashMap<KeyId, Metablock>>> {
    let mut metadata_verified = HashMap::new();

    for step in &layout.steps {
        // Verify this single step, return verified links.
        let metadata_per_step_verified = verify_link_signature_thresholds_step(
            step,
            steps_links_metadata
                .get(&step.name)
                .unwrap_or(&HashMap::new()),
            &layout.keys,
        )?;

        metadata_verified.insert(step.name.clone(), metadata_per_step_verified);
    }

    Ok(metadata_verified)
}

/// verify_sublayouts will check if any step has been
/// delegated by the functionary, recurses into the delegation and
/// replaces the layout object in the chain_link_dict by an
/// equivalent link object.
fn verify_sublayouts(
    layout: &LayoutMetadata,
    chain_link_dict: HashMap<String, HashMap<KeyId, Metablock>>,
    link_dir: &str,
) -> Result<HashMap<String, HashMap<KeyId, LinkMetadata>>> {
    let mut steps_link_metadata = HashMap::new();
    for (step_name, key_link_dict) in chain_link_dict {
        let mut link_per_step = HashMap::new();
        for (keyid, link) in &key_link_dict {
            let link_metadata = match &link.metadata {
                MetadataWrapper::Layout(_) => {
                    // If it's a layout, go ahead.
                    debug!("Verifying sublayout {}...", step_name);
                    let mut layout_key_dict = HashMap::new();
                    let pubkey = layout.keys.get(keyid).ok_or_else(|| {
                        Error::VerificationFailure(format!("Can not find public key {:?}", keyid))
                    })?;
                    layout_key_dict.insert(keyid.to_owned(), pubkey.clone());

                    let sub_link_dir = format!("{step_name}.{}", keyid.prefix());

                    let sublayout_link_dir_path = Path::new(link_dir).join(&sub_link_dir);

                    let sublayout_link_dir_path =
                        sublayout_link_dir_path.to_str().ok_or_else(|| {
                            Error::VerificationFailure(format!(
                                "failed to convert dir {} in {}",
                                &sub_link_dir, link_dir
                            ))
                        })?;

                    let summary_link = in_toto_verify(
                        link,
                        layout_key_dict,
                        sublayout_link_dir_path,
                        Some(&step_name),
                    )?;

                    match summary_link.metadata {
                        MetadataWrapper::Layout(_) => panic!("unexpected layout"),
                        MetadataWrapper::Link(inner) => inner,
                    }
                }
                MetadataWrapper::Link(inner) => inner.clone(),
            };

            link_per_step.insert(keyid.clone(), link_metadata);
        }
        steps_link_metadata.insert(step_name.clone(), link_per_step);
    }

    Ok(steps_link_metadata)
}

/// verify_all_steps_command_alignment will iteratively check if all
/// expected commands as defined in the Steps of a Layout align with
/// the actual commands as recorded in the Link metadata.
fn verify_all_steps_command_alignment(
    layout: &LayoutMetadata,
    link_files: &HashMap<String, HashMap<KeyId, LinkMetadata>>,
) -> Result<()> {
    for step in &layout.steps {
        let expected_command = &step.expected_command;
        let key_link_dict = link_files.get(&step.name).ok_or_else(|| {
            Error::VerificationFailure(format!("can not find LinkMetadata of step {}", step.name))
        })?;
        for link in key_link_dict.values() {
            let command = &link.command;
            if *command != *expected_command {
                warn!(
                    "Run command {:?} different from expected command {:?}",
                    command, expected_command
                );
            }
        }
    }

    Ok(())
}

/// verify_threshold_constraints will verify that all links
/// corresponding to a given step report the same materials
/// and products.
fn verify_threshold_constraints(
    layout: &LayoutMetadata,
    link_files: &HashMap<String, HashMap<KeyId, LinkMetadata>>,
) -> Result<()> {
    for step in &layout.steps {
        if step.threshold <= 1 {
            info!(
                "Skipping threshold verification for step '{}' with threshold {}.",
                step.name, step.threshold
            );
            continue;
        }

        let key_link_per_step = link_files.get(&step.name).ok_or_else(|| {
            Error::VerificationFailure(format!("step {} does not have validated links.", step.name))
        })?;
        if key_link_per_step.len() < step.threshold as usize {
            return Err(Error::VerificationFailure(format!(
                "step {} does not be performed by enough functionaries.",
                step.name
            )));
        }

        let reference_keyid = key_link_per_step.keys().next().ok_or_else(|| {
            Error::VerificationFailure(format!("step {} does not have enough key ids.", step.name))
        })?;
        let reference_link = &key_link_per_step[reference_keyid];

        for link in key_link_per_step.values() {
            if link.materials != reference_link.materials
                || link.products != reference_link.products
            {
                return Err(Error::VerificationFailure(format!(
                    "Links {} have different artifacts.",
                    link.name
                )));
            }
        }
    }

    Ok(())
}

/// reduce_chain_links will iterates through the passed
/// chain_link_dict and builds a dict with step-name as
/// keys and link objects as values. We already check if
/// the links of different functionaries are identical.
fn reduce_chain_links(
    link_files: HashMap<String, HashMap<KeyId, LinkMetadata>>,
) -> Result<HashMap<String, LinkMetadata>> {
    let mut res = HashMap::new();
    link_files.iter().try_for_each(|(k, v)| -> Result<()> {
        res.insert(
            k.clone(),
            v.values()
                .last()
                .ok_or_else(|| {
                    Error::VerificationFailure(format!(
                        "step {} does not have enough LinkMetadata.",
                        k,
                    ))
                })?
                .clone(),
        );
        Ok(())
    })?;

    Ok(res)
}

/// verify_all_item_rules will iteratively verify artifact rules
/// of passed steps.
fn verify_all_item_rules(
    steps: &Vec<Box<dyn SupplyChainItem>>,
    reduced_link_files: &HashMap<String, LinkMetadata>,
) -> Result<()> {
    for step in steps {
        apply_rules_on_link(step, reduced_link_files)?;
    }

    Ok(())
}

/// run_all_inspections will extracts all inspections from a passed
/// Layout's inspect field and iteratively run each command defined
/// in the Inspection's `run` field using `runlib::in_toto_run`, which
/// returns a Metablock object containing a Link object.
fn run_all_inspections(layout: &LayoutMetadata) -> Result<HashMap<String, LinkMetadata>> {
    let material_paths = ["."];
    let product_paths = ["."];
    let mut inspection_links = HashMap::new();

    for inspect in &layout.inspect {
        let cmd_args: Vec<&str> = inspect.run.as_ref().iter().map(|arg| &arg[..]).collect();

        let metablock = in_toto_run(
            inspect.name(),
            Some("."),
            &material_paths,
            &product_paths,
            &cmd_args,
            None,
            None,
            None,
        )?;

        // dump the metadata
        let filename = format!("{}.link", inspect.name());
        std::fs::write(filename, serde_json::to_string_pretty(&metablock)?)?;

        // record in the hashmap
        let link_metadata = match metablock.metadata {
            MetadataWrapper::Layout(_) => panic!("Unexpected layout."),
            MetadataWrapper::Link(inner) => inner,
        };

        inspection_links.insert(inspect.name().to_string(), link_metadata);
    }

    Ok(inspection_links)
}

fn get_summary_link(
    layout: &LayoutMetadata,
    reduced_link_files: &HashMap<String, LinkMetadata>,
    name: &str,
) -> Result<Metablock> {
    let builder = LinkMetadataBuilder::new();
    let link_metadata = match layout.steps.is_empty() {
        true => builder.build()?,
        false => builder
            .materials(reduced_link_files[layout.steps[0].name()].materials.clone())
            .products(
                reduced_link_files[layout.steps[layout.steps.len() - 1].name()]
                    .products
                    .clone(),
            )
            .byproducts(
                reduced_link_files[layout.steps[layout.steps.len() - 1].name()]
                    .byproducts
                    .clone(),
            )
            .command(
                reduced_link_files[layout.steps[layout.steps.len() - 1].name()]
                    .command
                    .clone(),
            )
            .name(name.to_string())
            .build()?,
    };
    Metablock::new(MetadataWrapper::Link(link_metadata), &[])
}

/// in_toto_verify can be used to verify an entire software supply chain according to
/// the in-toto specification v0.9. It requires the metadata of the root layout, a map
/// that contains public keys to verify the root layout signatures, a path to a
/// directory from where it can load link metadata files, which are treated as
/// signed evidence for the steps defined in the layout, a step name, and a
/// parameter dictionary used for parameter substitution. The step name only
/// matters for sublayouts, where it's important to associate the summary of that
/// step with a unique name. The verification routine is as follows:
///
/// 1. Verify layout signature(s) using passed key(s)
/// 2. Verify layout expiration date
/// // 3. Substitute parameters in layout
/// 3. Load link metadata files for steps of layout
/// 4. Verify signatures and signature thresholds for steps of layout
/// 5. Verify sublayouts recursively
/// 6. Verify command alignment for steps of layout (only warns)
/// 7. Verify artifact rules for steps of layout
/// 8. Execute inspection commands (generates link metadata for each inspection)
/// 9. Verify artifact rules for inspections of layout
///
/// in_toto_verify returns a summary link wrapped in a Metablock object or an error.
/// If any of the verification routines fail, verification is aborted and error is
/// returned.
///
/// # Parameters
/// * `layout`: The LayoutMetadata wrapped in a Metablock.
/// * `layout_keys`: A `key_id` to `Pubkey` map defined in layout.
/// * `link_dir`: The directory where link files are stored.
/// * `step_name`(Optional): A name assigned to the returned link. This is mostly
/// useful during recursive sublayout verification.
///
/// # Side-Effects
/// * I/O: Read link files from the disk.
/// * Process: Run commands using subprocess.
///
/// # Return Value
/// * A LinkMetadata which summarizes the materials
/// and products of the whole software supply chain.
pub fn in_toto_verify(
    layout: &Metablock,
    layout_keys: HashMap<KeyId, PublicKey>,
    link_dir: &str,
    step_name: Option<&str>,
) -> Result<Metablock> {
    // Verify layout signature(s) using passed key(s) and
    // judge whether the Metablock has layout inside
    let layout = match verify_layout_signatures(layout, &layout_keys)? {
        MetadataWrapper::Layout(inner) => inner,
        _ => {
            return Err(Error::IllegalArgument(
                "The input Metablock is not a layout.".to_string(),
            ))
        }
    };

    // Verify layout expiration date
    verify_layout_expiration(&layout)?;

    // Load metadata files for steps of layout
    let steps_links_metadata = load_links_for_layout(&layout, link_dir)?;

    // Verify signatures and signature thresholds for steps of layout
    let link_files = verify_link_signature_thresholds(&layout, steps_links_metadata)?;

    // Verify sublayouts recursively
    let link_files = verify_sublayouts(&layout, link_files, link_dir)?;

    // Verify command alignment for steps of layout (only warns)
    verify_all_steps_command_alignment(&layout, &link_files)?;

    // Verify threshold
    verify_threshold_constraints(&layout, &link_files)?;

    // Reduce link files
    let mut reduced_link_files = reduce_chain_links(link_files)?;

    let steps = layout
        .steps
        .iter()
        .map(|step| Box::new(step.clone()) as Box<dyn SupplyChainItem>)
        .collect();
    // Verify artifact rules for steps of layout
    verify_all_item_rules(&steps, &reduced_link_files)?;

    // Execute inspection commands (generates link metadata for each inspection)
    let inspection_link_files = run_all_inspections(&layout)?;
    reduced_link_files.extend(inspection_link_files);

    let inspects = layout
        .inspect
        .iter()
        .map(|step| Box::new(step.clone()) as Box<dyn SupplyChainItem>)
        .collect();

    // Verify artifact rules for inspections of layout
    verify_all_item_rules(&inspects, &reduced_link_files)?;

    get_summary_link(&layout, &reduced_link_files, step_name.unwrap_or(""))
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs, str::FromStr};

    use crate::{
        crypto::{KeyId, PublicKey, SignatureScheme},
        error::Error::VerificationFailure,
        models::Metablock,
    };
    use std::path::Path;

    use super::in_toto_verify;

    #[test]
    fn verify_demo() {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let working_dir = Path::new(&manifest_dir)
            .join("tests")
            .join("test_verifylib")
            .join("workdir");

        let root_layout_file = working_dir.join("root.layout");
        let raw = fs::read(root_layout_file).expect("read layout failed");
        let layout =
            serde_json::from_slice::<Metablock>(&raw).expect("deserialize metablock failed");
        let public_key_file = working_dir.join("alice.pub");
        let public_key_string =
            fs::read_to_string(public_key_file).expect("read public key failed");
        let pem = pem::parse(public_key_string).expect("parse pem failed");
        let pub_key = PublicKey::from_spki(pem.contents(), SignatureScheme::RsaSsaPssSha256)
            .expect("create public key failed");
        let key_id =
            KeyId::from_str("556caebdc0877eed53d419b60eddb1e57fa773e4e31d70698b588f3e9cc48b35")
                .expect("key id parse failed");
        let layout_keys = HashMap::from([(key_id, pub_key)]);
        let result = in_toto_verify(&layout, layout_keys, "../links", None);
        match result {
            Ok(_) => {}
            Err(VerificationFailure(msg)) => assert!(msg == "layout expired"),
            Err(error) => panic!("{}", error),
        }
    }
}
