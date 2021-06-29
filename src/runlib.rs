//! A tool that functionaries can use to create link metadata about a step.

use crate::Result;
use crate::{
    crypto::PrivateKey,
    interchange::Json,
    models::{LinkMetadata, LinkMetadataBuilder, SignedMetadata, VirtualTargetPath},
};

/// InTotoRun is a function that executes commands on a software supply chain step
/// (layout inspection coming soon), then generates and returns its corresponding Link metadata.
pub fn InTotoRun(
    name: &str,
    run_dir: &str, // Directory to execute the commands
    material_paths: &[&str],
    product_paths: &[&str],
    cmd_args: &[&str],
    key: PrivateKey,
    hash_algorithms: &[&str], // TODO additional hash algorithms supported
) -> Result<SignedMetadata<Json, LinkMetadata>> {

    // TODO Record Materials: Given the material_paths, recursively traverse and record files in given path(s)
        // For each file it comes across, hash it using the default hash algorithm & other algorithm supplied
        // Record that hash value in BTreeMap format
        // Potential pain point: soft links

    // TODO Execute commands provided in cmd_args
        // Iterate through each command in cmd_args.
            // For each command, execute it.

    // TODO Record Products: Given the product_paths, recursively traverse and record files in given path(s)
        // For each file it comes across, hash it using the default hash algorithm & other algorithm supplied
            // Record that hash value in BTreeMap format
            // Potential pain point: soft links

    // TODO Create link based on values collected above
        // let mut link = LinkMetadataBuilder::new().name(name.to_string());
        // Add material
            // link = link.add_material(VirtualTargetPath::new(m.to_string()).unwrap())
        // Add product
            // link = link.add_product(VirtualTargetPath::new(p.to_string()).unwrap());

    // TODO. Check inputs are valid. If so, record inputs into link (generate link)
    // Validation should be built into the LinkMetadataBuilder

    // TODO (Optional) Sign the link with key param supplied
        // If no key param supplied, return link
            // Ok(link)
        // Else
            //let signed_link = link.signed::<Json>(&key).unwrap();
            // Return Signed Link
            // Ok(signed_link)
}
