use in_toto::{
    crypto::{KeyType, PrivateKey, SignatureScheme},
    interchange::Json,
    models::{byproducts::ByProducts, LinkMetadataBuilder, VirtualTargetPath},
    runlib::in_toto_run,
};
use std::fs::{canonicalize, write};
use std::os::unix::fs;
use tempfile::tempdir;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    pub static ref TEST_KEY: Vec<u8> = PrivateKey::new(KeyType::Ed25519).unwrap();
    pub static ref TEST_PRIVATE_KEY: PrivateKey = PrivateKey::from_pkcs8(
        &PrivateKey::new(KeyType::Ed25519).unwrap(),
        SignatureScheme::Ed25519
    )
    .unwrap();
}

/* TODO ERRORS
- Signature Values don't match up
- "IllegalArgument("Cannot start with \'/\'")', tests/runlib.rs:38:5" error -> workaround added using tempdir
*/

// Default link generated Metablock like step_name and default key

/*
Test Cases
- in_toto_run_record_file
- in_toto_run_record_new_file
- in_toto_run_record_modified_file (TODO)
- in_toto_run_record_symlink_file (TODO)
- in_toto_run_record_symlink_cycle (TODO)
- in_toto_run_handle_nonexistent_materials (TODO)
- in_toto_run_test_key_signature (TODO)
- One test where things *fail*
*/

#[test]
fn in_toto_run_record_file() {
    // Initialization
    let dir = tempdir().unwrap();
    let dir_canonical = canonicalize(dir.path()).unwrap();
    let dir_path = dir_canonical.to_str().unwrap();

    // Create file
    write(format!("{}/foo.txt", dir_path), "lorem ipsum").unwrap();
    print!("Path: {}\n", dir_path);

    // Expected value
    let byproducts = ByProducts::new()
        .set_return_value(0)
        .set_stderr(String::from(""))
        .set_stdout(String::from("in_toto says hi\n"));
    let expected = LinkMetadataBuilder::new()
        .name(String::from("test"))
        .byproducts(byproducts)
        .add_material(VirtualTargetPath::new(format!("{}/foo.txt", dir_path)).unwrap())
        .add_product(VirtualTargetPath::new(format!("{}/foo.txt", dir_path)).unwrap())
        .signed::<Json>(&TEST_PRIVATE_KEY)
        .unwrap();

    // Result value
    let result = in_toto_run(
        "test",
        None,
        &vec![dir_path],
        &vec![dir_path],
        &["sh", "-c", "echo 'in_toto says hi'"],
        Some(&TEST_PRIVATE_KEY),
        None,
        None,
    )
    .unwrap();

    assert_eq!(expected, result);

    // Clean-up
    dir.close().unwrap();
}

#[test]
fn in_toto_run_record_new_file() {
    // Initialization
    let dir = tempdir().unwrap();
    let dir_canonical = canonicalize(dir.path()).unwrap();
    let dir_path = dir_canonical.to_str().unwrap();

    // Create file
    write(format!("{}/foo.txt", dir_path), "lorem ipsum").unwrap();
    print!("Path: {}\n", dir_path);

    // Result Value
    let result = in_toto_run(
        "test",
        None,
        &vec![dir_path],
        &vec![dir_path],
        &[
            "sh",
            "-c",
            &format!("echo 'in_toto says hi' >> {}/bar.txt", dir_path),
        ],
        Some(&TEST_PRIVATE_KEY),
        None,
        None,
    )
    .unwrap();

    let byproducts = ByProducts::new()
        .set_return_value(0)
        .set_stderr(String::from(""))
        .set_stdout(String::from(""));

    // Expected value
    let expected = LinkMetadataBuilder::new()
        .name(String::from("test"))
        .add_material(VirtualTargetPath::new(format!("{}/foo.txt", dir_path)).unwrap())
        .add_product(VirtualTargetPath::new(format!("{}/foo.txt", dir_path)).unwrap())
        .add_product(VirtualTargetPath::new(format!("{}/bar.txt", dir_path)).unwrap())
        .byproducts(byproducts)
        .signed::<Json>(&TEST_PRIVATE_KEY)
        .unwrap();

    assert_eq!(expected, result);

    // Clean-up work
    dir.close().unwrap();
}

#[test]
fn in_toto_run_new_line_in_stdout() {
    // Initialization
    let dir = tempdir().unwrap();
    let dir_canonical = canonicalize(dir.path()).unwrap();
    let dir_path = dir_canonical.to_str().unwrap();

    // Create file
    write(format!("{}/foo.txt", dir_path), "lorem ipsum").unwrap();

    let byproducts = ByProducts::new()
        .set_return_value(0)
        .set_stderr(String::from(""))
        .set_stdout(String::from("Cloning into 'some-project'...\n"));

    let link = LinkMetadataBuilder::new()
        .name(String::from("test"))
        .add_material(VirtualTargetPath::new(format!("{}/foo.txt", dir_path)).unwrap())
        .add_product(VirtualTargetPath::new(format!("{}/foo.txt", dir_path)).unwrap())
        .byproducts(byproducts)
        .signed::<Json>(&TEST_PRIVATE_KEY)
        .unwrap();

    assert!(link.verify(1, [TEST_PRIVATE_KEY.public()]).is_ok());

    // Clean-up work
    dir.close().unwrap();
}

#[test]
fn in_toto_run_record_modified_file() {
    // TODO
}

#[test]
fn in_toto_run_record_symlink_file() {
    // Initialization
    let dir = tempdir().unwrap();
    let dir_canonical = canonicalize(dir.path()).unwrap();
    let dir_path = dir_canonical.to_str().unwrap();

    // Create symlink file
    write(format!("{}/foo.txt", dir_path), "lorem ipsum").unwrap();
    fs::symlink(
        format!("{}/foo.txt", dir_path),
        format!("{}/symfile.txt", dir_path),
    )
    .unwrap();

    print!("Path: {}\n", dir_path);

    let byproducts = ByProducts::new()
        .set_return_value(0)
        .set_stderr(String::from(""))
        .set_stdout(String::from("in_toto says hi\n"));

    // Expected value
    let expected = LinkMetadataBuilder::new()
        .name(String::from("test"))
        .add_material(VirtualTargetPath::new(format!("{}/foo.txt", dir_path)).unwrap())
        .add_material(VirtualTargetPath::new(format!("{}/symfile.txt", dir_path)).unwrap())
        .add_product(VirtualTargetPath::new(format!("{}/foo.txt", dir_path)).unwrap())
        .add_product(VirtualTargetPath::new(format!("{}/symfile.txt", dir_path)).unwrap())
        .byproducts(byproducts)
        .signed::<Json>(&TEST_PRIVATE_KEY)
        .unwrap();

    // Result Value
    let result = in_toto_run(
        "test",
        None,
        &vec![dir_path],
        &vec![dir_path],
        &["sh", "-c", "echo 'in_toto says hi'"],
        Some(&TEST_PRIVATE_KEY),
        None,
        None,
    )
    .unwrap();

    assert_eq!(expected, result);

    // Clean-up work
    dir.close().unwrap();
}

#[test]
fn in_toto_run_record_symlink_cycle() {
    // TODO
}
