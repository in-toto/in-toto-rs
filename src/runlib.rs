//! A tool that functionaries can use to create link metadata about a step.

use std::collections::BTreeMap;
use std::fs::{canonicalize as canonicalize_path, metadata, File};
use std::io::{self, BufReader, Write};
use std::process::Command;
use walkdir::WalkDir;

use crate::models::{Link, TargetDescription};
use crate::{
    crypto,
    crypto::PrivateKey,
    models::{LinkMetadataBuilder, VirtualTargetPath},
};
use crate::{Error, Result};

/// record_artifacts is a function that traverses through the passed slice of paths, hashes the content of files
/// encountered, and returns the path and hashed content in BTreeMap format, wrapped in Result.
/// If a step in record_artifact fails, the error is returned.
pub fn record_artifacts(
    paths: &[&str],
    // hash_algorithms: Option<&[&str]>,
) -> Result<BTreeMap<VirtualTargetPath, TargetDescription>> {
    // Initialize artifacts
    let mut artifacts: BTreeMap<VirtualTargetPath, TargetDescription> = BTreeMap::new();

    // For each path provided, walk the directory and add all files to artifacts
    for path in paths {
        for entry in WalkDir::new(path) {
            let entry = match entry {
                Ok(content) => content,
                Err(error) => {
                    return Err(Error::from(io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Walkdir Error: {}", error),
                    )))
                }
            };
            let entry_path = entry.path();

            // TODO: Handle soft/symbolic links, by default is they are ignored, but we should visit them just once

            // If entry is a file, open and hash the file
            let md = metadata(entry_path)?;
            if md.is_file() {
                let file = File::open(entry_path)?;
                let mut reader = BufReader::new(file);
                // TODO: handle optional hash_algorithms input
                let (_length, hashes) =
                    crypto::calculate_hashes(&mut reader, &[crypto::HashAlgorithm::Sha256])?;

                if let Some(path) = entry_path.to_str() {
                    // TODO: normalize path instead of explicit checking
                    // TODO: normalize path from the current directory instead of absolute path from root.
                    // Canonicalize path doesn't work because Rust does not have enough support for it, see https://github.com/rust-lang/rfcs/issues/2208
                    let cleaned_path = if &path[0..2] == "./" {
                        &path[2..]
                    } else {
                        &path
                    };
                    artifacts.insert(VirtualTargetPath::new(String::from(cleaned_path))?, hashes);
                }
            }
        }
    }
    Ok(artifacts)
}

/// run_command is a function that, given command arguments, executes commands on a software supply chain step
/// and returns the stdout and stderr as byproducts.
/// The first element of cmd_args is used as executable and the rest as command arguments.
/// If a commands in run_command fails to execute, the error is returned.
pub fn run_command(cmd_args: &[&str], run_dir: Option<&str>) -> Result<BTreeMap<String, String>> {
    let executable = cmd_args[0];
    let args = (&cmd_args[1..])
        .iter()
        .map(|arg| {
            if VirtualTargetPath::new((*arg).into()).is_ok() {
                let absolute_path = canonicalize_path(*arg);
                match absolute_path {
                    Ok(path_buf) => match path_buf.to_str() {
                        Some(p) => p,
                        None => *arg,
                    },
                    Err(_) => *arg,
                };
            }
            *arg
        })
        .collect::<Vec<&str>>();

    let mut cmd = Command::new(executable);
    let mut cmd = cmd.args(args);

    if let Some(dir) = run_dir {
        cmd = cmd.current_dir(dir)
    }

    let output = cmd.output()?;

    // Emit stdout, stderror
    io::stdout().write_all(&output.stdout)?;
    io::stderr().write_all(&output.stderr)?;

    // Format output into Byproduct
    let mut byproducts: BTreeMap<String, String> = BTreeMap::new();
    // Write to byproducts
    let stdout = match String::from_utf8(output.stdout) {
        Ok(output) => output,
        Err(error) => {
            return Err(Error::from(io::Error::new(
                std::io::ErrorKind::Other,
                format!("Utf8Error: {}", error),
            )))
        }
    };
    let stderr = match String::from_utf8(output.stderr) {
        Ok(output) => output,
        Err(error) => {
            return Err(Error::from(io::Error::new(
                std::io::ErrorKind::Other,
                format!("Utf8Error: {}", error),
            )))
        }
    };
    let status = match output.status.code() {
        Some(code) => code.to_string(),
        None => "Process terminated by signal".to_string(),
    };

    byproducts.insert("stdout".to_string(), stdout);
    byproducts.insert("stderr".to_string(), stderr);
    byproducts.insert("return-value".to_string(), status);

    Ok(byproducts)
}

// TODO: implement default trait for in_toto_run's parameters

/// in_toto_run is a function that executes commands on a software supply chain step
/// (layout inspection coming soon), then generates and returns its corresponding Link metadata.
pub fn in_toto_run(
    name: &str,
    run_dir: Option<&str>,
    material_paths: &[&str],
    product_paths: &[&str],
    cmd_args: &[&str],
    key: Option<PrivateKey>,
    // env: Option<BTreeMap<String, String>>
    // hash_algorithms: Option<&[&str]>,
) -> Result<Link> {
    // Record Materials: Given the material_paths, recursively traverse and record files in given path(s)
    let materials = record_artifacts(material_paths)?;

    // Execute commands provided in cmd_args
    let byproducts = run_command(cmd_args, run_dir)?;

    // Record Products: Given the product_paths, recursively traverse and record files in given path(s)
    let products = record_artifacts(product_paths)?;

    // Create link based on values collected above
    let link_metadata_builder = LinkMetadataBuilder::new()
        .name(name.to_string())
        .materials(materials)
        .byproducts(byproducts)
        .products(products);
    let link_metadata = link_metadata_builder.build()?;

    // TODO Sign the link with key param supplied. If no key param supplied, build & return link
    /* match key {
        Some(k)   => {
            // TODO: SignedMetadata and Link are different types. Need to consolidate
            let signed_link = link_metadata_builder.signed::<Json>(&k).unwrap();
            let json = serde_json::to_value(&signed_link).unwrap();
        },
        None => {
        }
    } */
    Link::from(&link_metadata)
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use data_encoding::HEXLOWER;

    use super::*;

    fn create_target_description(
        hash_algorithm: crypto::HashAlgorithm,
        hash_value: &[u8],
    ) -> TargetDescription {
        let mut hash = HashMap::new();
        hash.insert(
            hash_algorithm,
            crypto::HashValue::new(HEXLOWER.decode(hash_value).unwrap()),
        );
        hash
    }

    #[test]
    fn test_record_artifacts() {
        let mut expected: BTreeMap<VirtualTargetPath, TargetDescription> = BTreeMap::new();
        expected.insert(
            VirtualTargetPath::new("tests/test_runlib/.hidden/foo".to_string()).unwrap(),
            create_target_description(
                crypto::HashAlgorithm::Sha256,
                b"7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
            ),
        );
        expected.insert(
            VirtualTargetPath::new("tests/test_runlib/.hidden/.bar".to_string()).unwrap(),
            create_target_description(
                crypto::HashAlgorithm::Sha256,
                b"b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c",
            ),
        );
        expected.insert(
            VirtualTargetPath::new("tests/test_runlib/hello./world".to_string()).unwrap(),
            create_target_description(
                crypto::HashAlgorithm::Sha256,
                b"25623b53e0984428da972f4c635706d32d01ec92dcd2ab39066082e0b9488c9d",
            ),
        );
        assert_eq!(record_artifacts(&["tests/test_runlib"]).unwrap(), expected);
        assert_eq!(record_artifacts(&["tests"]).is_ok(), true);
        assert_eq!(record_artifacts(&["file-does-not-exist"]).is_err(), true);
    }

    #[test]
    fn test_run_command() {
        let byproducts = run_command(&["sh", "-c", "printf hello"], Some("tests")).unwrap();
        let mut expected = BTreeMap::new();
        expected.insert("stdout".to_string(), "hello".to_string());
        expected.insert("stderr".to_string(), "".to_string());
        expected.insert("return-value".to_string(), "0".to_string());

        assert_eq!(byproducts, expected);

        assert_eq!(
            run_command(&["command-does-not-exist", "true"], None).is_err(),
            true
        );
    }
}
