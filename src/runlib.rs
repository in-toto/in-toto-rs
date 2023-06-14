//! A tool that functionaries can use to create link metadata about a step.

use path_clean::clean;
use std::collections::{BTreeMap, HashSet};
use std::fs::{canonicalize as canonicalize_path, symlink_metadata, File};
use std::io::{self, BufReader, Write};
use std::process::Command;
use walkdir::WalkDir;

use crate::crypto::HashAlgorithm;
use crate::interchange::Json;
use crate::models::byproducts::ByProducts;
use crate::models::{Metablock, TargetDescription};
use crate::{
    crypto,
    crypto::PrivateKey,
    models::{LinkMetadataBuilder, VirtualTargetPath},
};
use crate::{Error, Result};

/// Reads and hashes an artifact given its path as a string literal,
/// returning the `VirtualTargetPath` and `TargetDescription` of the file as a tuple, wrapped in `Result`.
pub fn record_artifact(
    path: &str,
    hash_algorithms: &[HashAlgorithm],
    lstrip_paths: Option<&[&str]>,
) -> Result<(VirtualTargetPath, TargetDescription)> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let (_length, hashes) = crypto::calculate_hashes(&mut reader, hash_algorithms)?;
    let lstripped_path = apply_left_strip(path, lstrip_paths)?;
    Ok((VirtualTargetPath::new(lstripped_path)?, hashes))
}

/// Given an artifact path in `&str` format, left strip path for given artifact based an optional array of `lstrip_paths` provided,
/// returning the stripped file path in String format wrapped in `Result`.
fn apply_left_strip(path: &str, lstrip_paths: Option<&[&str]>) -> Result<String> {
    // If lstrip_paths is None, skip strip.
    // Else, check if path starts with any given lstrip paths and strip
    if lstrip_paths.is_none() {
        return Ok(String::from(path));
    }
    let l_paths = lstrip_paths.unwrap();
    let mut stripped_path = path;
    let mut find_prefix = "";
    for l_path in l_paths.iter() {
        if !path.starts_with(l_path) {
            continue;
        }
        // if find possible prefix longer than
        if !find_prefix.is_empty() && find_prefix.len() >= l_path.len() {
            continue;
        }
        stripped_path = path.strip_prefix(l_path).ok_or_else(|| {
            Error::from(io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Lstrip Error: error stripping {} from path {}",
                    l_path, path
                ),
            ))
        })?;
        find_prefix = l_path;
    }
    Ok(String::from(stripped_path))
}

/// Traverses through the passed array of paths, hashes the content of files
/// encountered, and returns the path and hashed content in `BTreeMap` format, wrapped in `Result`.
/// If a step in record_artifact fails, the error is returned.
/// # Arguments
///
/// * `paths` - An array of string slices (`&str`) that holds the paths to be traversed. If a symbolic link cycle is detected in the `paths` during traversal, it is skipped.
/// * `hash_algorithms` - An array of string slice (`&str`) wrapped in an `Option` that holds the hash algorithms to be used. If `None` is provided, Sha256 is assumed as default.
/// * `lstrip_paths` - An array of string slice (`&str`) wrapped in an `Option` that is left stripped from the path of every artifact that contains it.
///
/// # Examples
///
/// ```
/// // You can have rust code between fences inside the comments
/// // If you pass --test to `rustdoc`, it will even test it for you!
/// # use in_toto::runlib::{record_artifacts};
/// let materials = record_artifacts(&["tests/test_runlib"], None, None).unwrap();
/// ```
pub fn record_artifacts(
    paths: &[&str],
    hash_algorithms: Option<&[&str]>,
    lstrip_paths: Option<&[&str]>,
) -> Result<BTreeMap<VirtualTargetPath, TargetDescription>> {
    // Verify hash_algorithms inputs are valid
    let available_algorithms = HashAlgorithm::return_all();
    let hash_algorithms = match hash_algorithms {
        Some(hashes) => {
            let mut map = vec![];
            for hash in hashes {
                if !available_algorithms.contains_key(*hash) {
                    return Err(Error::UnknownHashAlgorithm((*hash).to_string()));
                }
                let value = available_algorithms.get(*hash).unwrap();
                map.push(value.clone());
            }
            map
        }
        None => vec![HashAlgorithm::Sha256],
    };
    let hash_algorithms = &hash_algorithms[..];

    // Initialize artifacts
    let mut artifacts: BTreeMap<VirtualTargetPath, TargetDescription> = BTreeMap::new();
    // For each path provided, walk the directory and add all files to artifacts
    for path in paths {
        // Normalize path
        let path = clean(path);
        let mut walker = WalkDir::new(path).follow_links(true).into_iter();
        let mut visited_sym_links = HashSet::new();
        while let Some(entry) = walker.next() {
            let path = dir_entry_to_path(entry)?;
            let file_type = std::fs::symlink_metadata(&path)?.file_type();
            // If entry is a symlink, check it's unvisited. If so, continue.
            if file_type.is_symlink() {
                if visited_sym_links.contains(&path) {
                    walker.skip_current_dir();
                } else {
                    visited_sym_links.insert(String::from(&path));
                    // s_path: the actual path the symbolic link is pointing to
                    let s_path = match std::fs::read_link(&path)?.as_path().to_str() {
                        Some(str) => String::from(str),
                        None => break,
                    };
                    if symlink_metadata(s_path)?.file_type().is_file() {
                        let (virtual_target_path, hashes) =
                            record_artifact(&path, hash_algorithms, lstrip_paths)?;
                        if artifacts.contains_key(&virtual_target_path) {
                            return Err(Error::LinkGatheringError(format!(
                                "non unique stripped path {}",
                                virtual_target_path.to_string()
                            )));
                        }
                        artifacts.insert(virtual_target_path, hashes);
                    }
                }
            }
            // If entry is a file, open and hash the file
            if file_type.is_file() {
                let (virtual_target_path, hashes) =
                    record_artifact(&path, hash_algorithms, lstrip_paths)?;
                if artifacts.contains_key(&virtual_target_path) {
                    return Err(Error::LinkGatheringError(format!(
                        "non unique stripped path {}",
                        virtual_target_path.to_string()
                    )));
                }
                artifacts.insert(virtual_target_path, hashes);
            }
        }
    }
    Ok(artifacts)
}

/// Given command arguments, executes commands on a software supply chain step
/// and returns the `stdout`, `stderr`, and `return-value` as `byproducts` in `Result<ByProducts>` format.
/// If a commands in run_command fails to execute, `Error` is returned.
/// # Arguments
///
/// * `cmd_args` - An array of string slices (`&str`) that holds the command arguments to be executed. The first element of cmd_args is used as executable and the rest as command arguments.
/// * `run_dir` - A string slice (`&str`) wrapped in an `Option` that holds the directory the commands are to be run in. If `None` is provided, the current directory is assumed as default.
///
/// # Examples
///
/// ```
/// // You can have rust code between fences inside the comments
/// // If you pass --test to `rustdoc`, it will even test it for you!
/// # use in_toto::runlib::{run_command};
/// let byproducts = run_command(&["sh", "-c", "printf hello"], Some("tests")).unwrap();
/// ```
pub fn run_command(cmd_args: &[&str], run_dir: Option<&str>) -> Result<ByProducts> {
    // Format output into Byproduct

    if cmd_args.is_empty() {
        return Ok(ByProducts::new());
    }

    let executable = cmd_args[0];
    let args = (cmd_args[1..])
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

    // TODO: Validate executable

    let mut cmd = Command::new(executable);
    let mut cmd = cmd.args(args);

    if let Some(dir) = run_dir {
        cmd = cmd.current_dir(dir)
    }

    let output = match cmd.output() {
        Ok(out) => out,
        Err(err) => {
            return Err(Error::IllegalArgument(format!(
                "Something went wrong with run_command inside in_toto_run. Error: {:?}",
                err
            )))
        }
    };

    // Emit stdout, stderror
    io::stdout().write_all(&output.stdout)?;
    io::stderr().write_all(&output.stderr)?;

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
    let status = output
        .status
        .code()
        .ok_or_else(|| Error::RunLibError("Process terminated by signal".to_string()))?;

    let byproducts = ByProducts::new()
        .set_stdout(stdout)
        .set_stderr(stderr)
        .set_return_value(status);

    Ok(byproducts)
}

// TODO: implement default trait for in_toto_run's parameters

/// Executes commands on a software supply chain step, then generates and returns its corresponding `LinkMetadata`
/// as a `Metablock` component, wrapped in `Result`.
/// If a symbolic link cycle is detected in the material or product paths, paths causing the cycle are skipped.
/// # Arguments
///
/// * `name` - The unique string used to associate link metadata with a step or inspection.
/// * `run_dir` - A string slice (`&str`) wrapped in an `Option` that holds the directory the commands are to be run in. If `None` is provided, the current directory is assumed as default.
/// * `material_paths` - A string slice (`&str`) of artifact paths to be recorded before command execution. Directories are traversed recursively.
/// * `product_paths` - A string slice (`&str`) of artifact paths to be recorded after command execution. Directories are traversed recursively.
/// * `cmd_args` - A string slice (`&str`) where the first element is a command and the remaining elements are arguments passed to that command.
/// * `key` -  A key used to sign the resulting link metadata.
/// * `hash_algorithms` - An array of string slice (`&str`) wrapped in an `Option` that holds the hash algorithms to be used. If `None` is provided, Sha256 is assumed as default.
/// * `lstrip_paths` - An array of string slice (`&str`) wrapped in an `Option` that is left stripped from the path of every artifact that contains it.
///
/// # Examples
///
/// ```
/// // You can have rust code between fences inside the comments
/// // If you pass --test to `rustdoc`, it will even test it for you!
/// # use in_toto::runlib::{in_toto_run};
/// # use in_toto::crypto::PrivateKey;
/// const ED25519_1_PRIVATE_KEY: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-1");
/// let key = PrivateKey::from_ed25519(ED25519_1_PRIVATE_KEY).unwrap();
/// let link = in_toto_run("example", Some("tests"), &["tests/test_runlib"], &["tests/test_runlib"],  &["sh", "-c", "echo 'in_toto says hi' >> hello_intoto"], Some(&key), Some(&["sha512", "sha256"]), Some(&["tests/test_runlib/"])).unwrap();
/// let json = serde_json::to_value(&link).unwrap();
/// println!("Generated link: {}", json);
/// ```
pub fn in_toto_run(
    name: &str,
    run_dir: Option<&str>,
    material_paths: &[&str],
    product_paths: &[&str],
    cmd_args: &[&str],
    key: Option<&PrivateKey>,
    hash_algorithms: Option<&[&str]>,
    lstrip_paths: Option<&[&str]>,
    // env: Option<BTreeMap<String, String>>
) -> Result<Metablock> {
    // Record Materials: Given the material_paths, recursively traverse and record files in given path(s)
    let materials = record_artifacts(material_paths, hash_algorithms, lstrip_paths)?;

    // Execute commands provided in cmd_args
    let byproducts = run_command(cmd_args, run_dir)?;

    // Record Products: Given the product_paths, recursively traverse and record files in given path(s)
    let products = record_artifacts(product_paths, hash_algorithms, lstrip_paths)?;

    // Create link based on values collected above
    let link_metadata_builder = LinkMetadataBuilder::new()
        .name(name.to_string())
        .materials(materials)
        .byproducts(byproducts)
        .products(products);

    // Sign the link with key param supplied. If no key is found, return Metablock with
    // no signatures (for inspection purposes)
    match key {
        Some(k) => link_metadata_builder.signed::<Json>(k),
        None => link_metadata_builder.unsigned::<Json>(),
    }
}

/// A private helper function that, given a `DirEntry`, return the entry's path as a `String`
/// wrapped in `Result`. If the entry's path is invalid, `Error` is returned.
fn dir_entry_to_path(
    entry: std::result::Result<walkdir::DirEntry, walkdir::Error>,
) -> Result<String> {
    let path = match entry {
        Ok(dir_entry) => match dir_entry.path().to_str() {
            Some(str) => String::from(str),
            None => {
                return Err(Error::IllegalArgument(format!(
                    "Invalid Path {}; non-UTF-8 string",
                    dir_entry.path().display()
                )))
            }
        },
        // If WalkDir errored, check if it's due to a symbolic link loop sighted,
        // if so, override the error and continue using the symbolic link path.
        // If this doesn't work, something hacky to consider would be reinvoking WalkDir
        // using the error_path as root.

        // Current behavior: when symbolic link is a directory and directly loops to parent,
        // it skips the symbolic link recording.
        // If this is not the desired behavior and we want to record the symbolic link's content
        // , we can probably do it in a hacky way by recursively calling record_artifacts and
        // extending the results to artifacts variable.
        Err(error) => {
            if error.loop_ancestor().is_some() {
                match error.path() {
                    None => {
                        return Err(Error::from(io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Walkdir Error: {}", error),
                        )))
                    }
                    Some(error_path) => {
                        let sym_path = match error_path.to_str() {
                            Some(str) => String::from(str),
                            None => {
                                return Err(Error::IllegalArgument(format!(
                                    "Invalid Path {}; non-UTF-8 string",
                                    error_path.display()
                                )))
                            }
                        };
                        // TODO: Emit a warning that a symlink cycle is detected and it will be skipped
                        // Add it to the link itself
                        sym_path
                    }
                }
            } else {
                return Err(Error::from(io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Walkdir Error: {}", error),
                )));
            }
        }
    };
    Ok(clean(path).into_os_string().into_string().unwrap())
}

#[cfg(test)]
mod test {
    use data_encoding::HEXLOWER;
    use std::collections::HashMap;

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
        assert_eq!(
            record_artifacts(&["tests/test_runlib"], None, None).unwrap(),
            expected
        );
        assert_eq!(record_artifacts(&["tests"], None, None).is_ok(), true);
        assert_eq!(
            record_artifacts(&["file-does-not-exist"], None, None).is_err(),
            true
        );
    }

    #[test]
    fn test_prefix_record_artifacts() {
        let mut expected: BTreeMap<VirtualTargetPath, TargetDescription> = BTreeMap::new();
        expected.insert(
            VirtualTargetPath::new("world".to_string()).unwrap(),
            create_target_description(
                crypto::HashAlgorithm::Sha256,
                b"25623b53e0984428da972f4c635706d32d01ec92dcd2ab39066082e0b9488c9d",
            ),
        );
        assert_eq!(
            record_artifacts(
                &["tests/test_prefix/left"],
                None,
                Some(&["tests/test_prefix/left/"])
            )
            .unwrap(),
            expected
        );
        // conflict of file "left/world" and "right/world"
        assert_eq!(
            record_artifacts(
                &["tests/test_prefix"],
                None,
                Some(&["tests/test_prefix/left/", "tests/test_prefix/right/"])
            )
            .is_err(),
            true
        );
    }

    #[test]
    fn test_left_strip() {
        let mut stripped_path: String;

        stripped_path = apply_left_strip(
            "tests/test_runlib/.hidden/foo",
            Some(&["tests/test_runlib"]),
        )
        .unwrap();
        assert_eq!(stripped_path, "/.hidden/foo");

        stripped_path = apply_left_strip(
            "tests/test_runlib/.hidden/foo",
            Some(&["tests/test_runlib/"]),
        )
        .unwrap();
        assert_eq!(stripped_path, ".hidden/foo");

        stripped_path = apply_left_strip(
            "tests/test_runlib/.hidden/foo",
            Some(&["tests/test_runlib/.hidden/"]),
        )
        .unwrap();
        assert_eq!(stripped_path, "foo");

        stripped_path = apply_left_strip(
            "tests/test_runlib/.hidden/foo",
            Some(&["path-does-not-exist"]),
        )
        .unwrap();
        assert_eq!(stripped_path, "tests/test_runlib/.hidden/foo");

        stripped_path = apply_left_strip(
            "tests/test_runlib/.hidden/foo",
            Some(&["path-does-not-exist", "tests/"]),
        )
        .unwrap();
        assert_eq!(stripped_path, "test_runlib/.hidden/foo");

        stripped_path = apply_left_strip(
            "tests/test_runlib/.hidden/foo",
            Some(&["tests/", "tests/test_runlib/.hidden/"]),
        )
        .unwrap();
        assert_eq!(stripped_path, "foo");
    }

    #[test]
    fn test_run_command() {
        let byproducts = run_command(&["sh", "-c", "printf hello"], Some("tests")).unwrap();
        let expected = ByProducts::new()
            .set_stderr("".to_string())
            .set_stdout("hello".to_string())
            .set_return_value(0);

        assert_eq!(byproducts, expected);

        assert_eq!(
            run_command(&["command-does-not-exist", "true"], None).is_err(),
            true
        );
    }
}
