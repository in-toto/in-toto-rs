//! in-toto metadata.

// use chrono::offset::Utc;
// use chrono::{DateTime, Duration};
use log::{debug, warn};
use serde::de::{Deserialize, DeserializeOwned, Deserializer, Error as DeserializeError};
use serde::ser::{Error as SerializeError, Serialize, Serializer};
use serde_derive::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, BTreeMap};
use std::fmt::{self, Debug, Display};
use std::io::Read;
use std::marker::PhantomData;
use std::str;
use std::fs::File;
use std::io::BufReader;


use crate::crypto::{self, HashAlgorithm, HashValue, KeyId, PrivateKey, PublicKey, Signature};
use crate::error::Error;
use crate::interchange::cjson::shims;
use crate::interchange::DataInterchange;
use crate::Result;

#[rustfmt::skip]
static PATH_ILLEGAL_COMPONENTS: &'static [&str] = &[
    ".", // current dir
    "..", // parent dir
         // TODO ? "0", // may translate to nul in windows
];

#[rustfmt::skip]
static PATH_ILLEGAL_COMPONENTS_CASE_INSENSITIVE: &'static [&str] = &[
    // DOS device files
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    "KEYBD$",
    "CLOCK$",
    "SCREEN$",
    "$IDLE$",
    "CONFIG$",
];

#[rustfmt::skip]
static PATH_ILLEGAL_STRINGS: &'static [&str] = &[
    ":", // for *nix compatibility
    "\\", // for windows compatibility
    "<",
    ">",
    "\"",
    "|",
    "?",
    "*",
    // control characters, all illegal in FAT
    "\u{000}",
    "\u{001}",
    "\u{002}",
    "\u{003}",
    "\u{004}",
    "\u{005}",
    "\u{006}",
    "\u{007}",
    "\u{008}",
    "\u{009}",
    "\u{00a}",
    "\u{00b}",
    "\u{00c}",
    "\u{00d}",
    "\u{00e}",
    "\u{00f}",
    "\u{010}",
    "\u{011}",
    "\u{012}",
    "\u{013}",
    "\u{014}",
    "\u{015}",
    "\u{016}",
    "\u{017}",
    "\u{018}",
    "\u{019}",
    "\u{01a}",
    "\u{01b}",
    "\u{01c}",
    "\u{01d}",
    "\u{01e}",
    "\u{01f}",
    "\u{07f}",
];

fn safe_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(Error::IllegalArgument("Path cannot be empty".into()));
    }

    if path.starts_with('/') {
        return Err(Error::IllegalArgument("Cannot start with '/'".into()));
    }

    for bad_str in PATH_ILLEGAL_STRINGS {
        if path.contains(bad_str) {
            return Err(Error::IllegalArgument(format!(
                "Path cannot contain {:?}",
                bad_str
            )));
        }
    }

    for component in path.split('/') {
        for bad_str in PATH_ILLEGAL_COMPONENTS {
            if component == *bad_str {
                return Err(Error::IllegalArgument(format!(
                    "Path cannot have component {:?}",
                    component
                )));
            }
        }

        let component_lower = component.to_lowercase();
        for bad_str in PATH_ILLEGAL_COMPONENTS_CASE_INSENSITIVE {
            if component_lower.as_str() == *bad_str {
                return Err(Error::IllegalArgument(format!(
                    "Path cannot have component {:?}",
                    component
                )));
            }
        }
    }

    Ok(())
}

/// The TUF role.
#[derive(Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    /// The link role
    #[serde(rename = "link")]
    Link,
    //#[serde(rename = "layout")]
    //Layout,
}

//struct Layout;

impl Role {
    /// Check if this role could be associated with a given path.
    ///
    /// ```
    /// use in_toto::metadata::{MetadataPath, Role};
    ///
    /// ```
    pub fn fuzzy_matches_path(&self, path: &MetadataPath) -> bool {
        match *self {
            Role::Link if &path.0 == "link" => true,
            //Role::Layout if &path.0 == "layout" => true,
            _ => false,
        }
    }

    /// Return the name of the role.
    pub fn name(&self) -> &'static str {
        match *self {
            //Role::Layout => "layout",
            Role::Link => "link",
        }
    }
}

impl Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Top level trait used for role metadata.
pub trait Metadata: Debug + PartialEq + Serialize + DeserializeOwned {
    /// The role associated with the metadata.
    const ROLE: Role;

    /// The version number.
    fn version(&self) -> u32;
}

/// Unverified raw metadata with attached signatures and type information identifying the
/// metadata's type and serialization format.
#[derive(Debug, Clone, PartialEq)]
pub struct RawSignedMetadata<D, M> {
    bytes: Vec<u8>,
    _marker: PhantomData<(D, M)>,
}

impl<D, M> RawSignedMetadata<D, M>
where
    D: DataInterchange,
    M: Metadata,
{
    /// Create a new [`RawSignedMetadata`] using the provided `bytes`.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }

    /// Access this metadata's inner raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Parse this metadata.
    pub fn parse(&self) -> Result<SignedMetadata<D, M>> {
        D::from_slice(&self.bytes)
    }
}

/// Helper to construct `SignedMetadata`.
#[derive(Debug, Clone)]
pub struct SignedMetadataBuilder<D, M>
where
    D: DataInterchange,
{
    signatures: HashMap<KeyId, Signature>,
    metadata: D::RawData,
    metadata_bytes: Vec<u8>,
    _marker: PhantomData<M>,
}

impl<D, M> SignedMetadataBuilder<D, M>
where
    D: DataInterchange,
    M: Metadata,
{
    /// Create a new `SignedMetadataBuilder` from a given `Metadata`.
    pub fn from_metadata(metadata: &M) -> Result<Self> {
        let metadata = D::serialize(metadata)?;
        Self::from_raw_metadata(metadata)
    }

    /// Create a new `SignedMetadataBuilder` from manually serialized metadata to be signed.
    /// Returns an error if `metadata` cannot be parsed into `M`.
    pub fn from_raw_metadata(metadata: D::RawData) -> Result<Self> {
        let _ensure_metadata_parses: M = D::deserialize(&metadata)?;
        let metadata_bytes = D::canonicalize(&metadata)?;
        Ok(Self {
            signatures: HashMap::new(),
            metadata,
            metadata_bytes,
            _marker: PhantomData,
        })
    }

    /// Sign the metadata using the given `private_key`, replacing any existing signatures with the
    /// same `KeyId`.
    ///
    /// **WARNING**: You should never have multiple TUF private keys on the same machine, so if
    /// you're using this to append several signatures at once, you are doing something wrong. The
    /// preferred method is to generate your copy of the metadata locally and use
    /// `SignedMetadata::merge_signatures` to perform the "append" operations.
    pub fn sign(mut self, private_key: &PrivateKey) -> Result<Self> {
        let sig = private_key.sign(&self.metadata_bytes)?;
        let _ = self.signatures.insert(sig.key_id().clone(), sig);
        Ok(self)
    }

    /// Construct a new `SignedMetadata` using the included signatures, sorting the signatures by
    /// `KeyId`.
    pub fn build(self) -> SignedMetadata<D, M> {
        let mut signatures = self
            .signatures
            .into_iter()
            .map(|(_k, v)| v)
            .collect::<Vec<_>>();
        signatures.sort_unstable_by(|a, b| a.key_id().cmp(b.key_id()));

        SignedMetadata {
            signatures,
            metadata: self.metadata,
            _marker: PhantomData,
        }
    }
}

/// Serialized metadata with attached unverified signatures.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedMetadata<D, M>
where
    D: DataInterchange,
{
    signatures: Vec<Signature>,
    #[serde(rename = "signed")]
    metadata: D::RawData,
    #[serde(skip_serializing, skip_deserializing)]
    _marker: PhantomData<M>,
}

impl<D, M> SignedMetadata<D, M>
where
    D: DataInterchange,
    M: Metadata,
{
    /// Create a new `SignedMetadata`. The supplied private key is used to sign the canonicalized
    /// bytes of the provided metadata with the provided scheme.
    ///
    /// ```
    /// # use chrono::prelude::*;
    /// # use in_toto::crypto::{PrivateKey, SignatureScheme, HashAlgorithm};
    /// # use in_toto::interchange::Json;
    /// # use in_toto::metadata::{SignedMetadata};
    /// #
    /// # fn main() {
    /// # let key: &[u8] = include_bytes!("../tests/ed25519/ed25519-1.pk8.der");
    /// let key = PrivateKey::from_pkcs8(&key, SignatureScheme::Ed25519).unwrap();
    ///
    /// # }
    /// ```
    pub fn new(metadata: &M, private_key: &PrivateKey) -> Result<Self> {
        let raw = D::serialize(metadata)?;
        let bytes = D::canonicalize(&raw)?;
        let sig = private_key.sign(&bytes)?;
        Ok(Self {
            signatures: vec![sig],
            metadata: raw,
            _marker: PhantomData,
        })
    }

    /// Serialize this metadata to canonical bytes suitable for serialization. Note that this
    /// method is only intended to serialize signed metadata generated by this crate, not to
    /// re-serialize metadata that was originally obtained from a remote source.
    ///
    /// TUF metadata hashes are on the raw bytes of the metadata, so it is not guaranteed that the
    /// hash of the returned bytes will match a hash included in, for example, a snapshot metadata
    /// file, as:
    /// * Parsing metadata removes unknown fields, which would not be included in the returned
    /// bytes,
    /// * DataInterchange implementations only guarantee the bytes are canonical for the purpose of
    /// a signature. Metadata obtained from a remote source may have included different whitespace
    /// or ordered fields in a way that is not preserved when parsing that metadata.
    pub fn to_raw(&self) -> Result<RawSignedMetadata<D, M>> {
        let bytes = D::canonicalize(&D::serialize(self)?)?;
        Ok(RawSignedMetadata::new(bytes))
    }

    /// Append a signature to this signed metadata. Will overwrite signature by keys with the same
    /// ID.
    ///
    /// **WARNING**: You should never have multiple TUF private keys on the same machine, so if
    /// you're using this to append several signatures at once, you are doing something wrong. The
    /// preferred method is to generate your copy of the metadata locally and use `merge_signatures`
    /// to perform the "append" operations.
    ///
    /// ```
    /// # use chrono::prelude::*;
    /// # use tuf::crypto::{PrivateKey, SignatureScheme, HashAlgorithm};
    /// # use tuf::interchange::Json;
    /// # use tuf::metadata::{SignedMetadata};
    /// #
    /// # fn main() {
    /// let key_1: &[u8] = include_bytes!("../tests/ed25519/ed25519-1.pk8.der");
    /// let key_1 = PrivateKey::from_pkcs8(&key_1, SignatureScheme::Ed25519).unwrap();
    ///
    /// // Note: This is for demonstration purposes only.
    /// // You should never have multiple private keys on the same device.
    /// let key_2: &[u8] = include_bytes!("../tests/ed25519/ed25519-2.pk8.der");
    /// let key_2 = PrivateKey::from_pkcs8(&key_2, SignatureScheme::Ed25519).unwrap();
    ///
    ///
    /// # }
    /// ```
    pub fn add_signature(&mut self, private_key: &PrivateKey) -> Result<()> {
        let bytes = D::canonicalize(&self.metadata)?;
        let sig = private_key.sign(&bytes)?;
        self.signatures
            .retain(|s| s.key_id() != private_key.key_id());
        self.signatures.push(sig);
        Ok(())
    }

    /// Merge the singatures from `other` into `self` if and only if
    /// `self.as_ref() == other.as_ref()`. If `self` and `other` contain signatures from the same
    /// key ID, then the signatures from `self` will replace the signatures from `other`.
    pub fn merge_signatures(&mut self, other: &Self) -> Result<()> {
        if self.metadata != other.metadata {
            return Err(Error::IllegalArgument(
                "Attempted to merge unequal metadata".into(),
            ));
        }

        let key_ids = self
            .signatures
            .iter()
            .map(|s| s.key_id().clone())
            .collect::<HashSet<KeyId>>();

        self.signatures.extend(
            other
                .signatures
                .iter()
                .filter(|s| !key_ids.contains(s.key_id()))
                .cloned(),
        );

        Ok(())
    }

    /// An immutable reference to the signatures.
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }


    /// Parse this metadata without verifying signatures.
    ///
    /// This operation is not safe to do with metadata obtained from an untrusted source.
    pub fn assume_valid(&self) -> Result<M> {
        D::deserialize(&self.metadata)
    }

    /// Verify this metadata.
    ///
    /// ```
    /// # use chrono::prelude::*;
    /// # use tuf::crypto::{PrivateKey, SignatureScheme, HashAlgorithm};
    /// # use tuf::interchange::Json;
    /// # use tuf::metadata::{SignedMetadata};
    ///
    /// # fn main() {
    /// let key_1: &[u8] = include_bytes!("../tests/ed25519/ed25519-1.pk8.der");
    /// let key_1 = PrivateKey::from_pkcs8(&key_1, SignatureScheme::Ed25519).unwrap();
    ///
    /// let key_2: &[u8] = include_bytes!("../tests/ed25519/ed25519-2.pk8.der");
    /// let key_2 = PrivateKey::from_pkcs8(&key_2, SignatureScheme::Ed25519).unwrap();
    ///
    ///
    /// # }
    pub fn verify<'a, I>(&self, threshold: u32, authorized_keys: I) -> Result<M>
    where
        I: IntoIterator<Item = &'a PublicKey>,
    {
        if self.signatures.is_empty() {
            return Err(Error::VerificationFailure(
                "The metadata was not signed with any authorized keys.".into(),
            ));
        }

        if threshold < 1 {
            return Err(Error::VerificationFailure(
                "Threshold must be strictly greater than zero".into(),
            ));
        }

        let authorized_keys = authorized_keys
            .into_iter()
            .map(|k| (k.key_id(), k))
            .collect::<HashMap<&KeyId, &PublicKey>>();

        let canonical_bytes = D::canonicalize(&self.metadata)?;

        let mut signatures_needed = threshold;
        // Create a key_id->signature map to deduplicate the key_ids.
        let signatures = self
            .signatures
            .iter()
            .map(|sig| (sig.key_id(), sig))
            .collect::<HashMap<&KeyId, &Signature>>();
        for (key_id, sig) in signatures {
            match authorized_keys.get(key_id) {
                Some(ref pub_key) => match pub_key.verify(&canonical_bytes, sig) {
                    Ok(()) => {
                        debug!("Good signature from key ID {:?}", pub_key.key_id());
                        signatures_needed -= 1;
                    }
                    Err(e) => {
                        warn!("Bad signature from key ID {:?}: {:?}", pub_key.key_id(), e);
                    }
                },
                None => {
                    warn!(
                        "Key ID {:?} was not found in the set of authorized keys.",
                        sig.key_id()
                    );
                }
            }
            if signatures_needed == 0 {
                break;
            }
        }
        if signatures_needed > 0 {
            return Err(Error::VerificationFailure(format!(
                "Signature threshold not met: {}/{}",
                threshold - signatures_needed,
                threshold
            )));
        }

        // "assume" the metadata is valid because we just verified that it is.
        self.assume_valid()
    }
}


/// The definition of what allows a role to be trusted.
#[derive(Clone, Debug, PartialEq)]
pub struct RoleDefinition {
    threshold: u32,
    key_ids: Vec<KeyId>,
}

impl RoleDefinition {
    /// Create a new `RoleDefinition` with a given threshold and set of authorized `KeyID`s.
    pub fn new(threshold: u32, key_ids: Vec<KeyId>) -> Result<Self> {
        if threshold < 1 {
            return Err(Error::IllegalArgument(format!("Threshold: {}", threshold)));
        }

        if key_ids.is_empty() {
            return Err(Error::IllegalArgument(
                "Cannot define a role with no associated key IDs".into(),
            ));
        }

        if (key_ids.len() as u64) < u64::from(threshold) {
            return Err(Error::IllegalArgument(format!(
                "Cannot have a threshold greater than the number of associated key IDs. {} vs. {}",
                threshold,
                key_ids.len()
            )));
        }

        Ok(RoleDefinition { threshold, key_ids })
    }

    /// The threshold number of signatures required for the role to be trusted.
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// An immutable reference to the set of `KeyID`s that are authorized to sign the role.
    pub fn key_ids(&self) -> &[KeyId] {
        &self.key_ids
    }
}

impl Serialize for RoleDefinition {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        shims::RoleDefinition::from(self)
            .map_err(|e| SerializeError::custom(format!("{:?}", e)))?
            .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for RoleDefinition {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::RoleDefinition = Deserialize::deserialize(de)?;
        intermediate
            .try_into()
            .map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

/// Wrapper for a path to metadata.
///
/// Note: This should **not** contain the file extension. This is automatically added by the
/// library depending on what type of data interchange format is being used.
///
/// ```
/// use tuf::metadata::MetadataPath;
///
/// // right
/// let _ = MetadataPath::new("root");
///
/// // wrong
/// let _ = MetadataPath::new("root.json");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct MetadataPath(String);

impl MetadataPath {
    /// Create a new `MetadataPath` from a `String`.
    ///
    /// ```
    /// # use tuf::metadata::MetadataPath;
    /// assert!(MetadataPath::new("foo").is_ok());
    /// assert!(MetadataPath::new("/foo").is_err());
    /// assert!(MetadataPath::new("../foo").is_err());
    /// assert!(MetadataPath::new("foo/..").is_err());
    /// assert!(MetadataPath::new("foo/../bar").is_err());
    /// assert!(MetadataPath::new("..foo").is_ok());
    /// assert!(MetadataPath::new("foo/..bar").is_ok());
    /// assert!(MetadataPath::new("foo/bar..").is_ok());
    /// ```
    pub fn new<P: Into<String>>(path: P) -> Result<Self> {
        let path = path.into();
        safe_path(&path)?;
        Ok(MetadataPath(path))
    }

    /// Create a metadata path from the given role.
    ///
    /// ```
    /// # use tuf::metadata::{Role, MetadataPath};
    ///            MetadataPath::new("root").unwrap());
    /// assert_eq!(MetadataPath::from_role(&Role::Targets),
    ///            MetadataPath::new("targets").unwrap());
    /// ```
    pub fn from_role(role: &Role) -> Self {
        Self::new(format!("{}", role)).unwrap()
    }

}

impl Display for MetadataPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for MetadataPath {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        MetadataPath::new(s).map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

/// Helper to construct `LinkMetadata`.
pub struct LinkMetadataBuilder {
    name: String,
    materials: BTreeMap<VirtualTargetPath, TargetDescription>,
    products: BTreeMap<VirtualTargetPath, TargetDescription>,
    env: BTreeMap<String, String>,
    byproducts: BTreeMap<String, String>,
}

impl LinkMetadataBuilder {

    // This should definitely be improved
    pub fn new() -> Self {
        LinkMetadataBuilder {
            name: String::new(),
            materials: BTreeMap::new(),
            products: BTreeMap::new(),
            env: BTreeMap::new(),
            byproducts: BTreeMap::new()
        }
    }

    /// Set the name number for this link 
    pub fn name(mut self, name: String) -> Self {
        self.name= name;
        self
    }

    /// Set the materials for this metadata 
    pub fn materials(mut self, materials: BTreeMap<VirtualTargetPath, TargetDescription>) -> Self {
        self.materials = materials;
        self
    }

    /// Set the products for this metadata 
    pub fn products(mut self, products: BTreeMap<VirtualTargetPath, TargetDescription>) -> Self {
        self.products = products;
        self
    }

    pub fn add_material(mut self, material_path: VirtualTargetPath) -> Self {
        let file = File::open(material_path.to_string()).unwrap();
        let mut reader = BufReader::new(file);
        let (_length, hashes) = crypto::calculate_hashes(&mut reader,
                &[crypto::HashAlgorithm::Sha256]).unwrap();
        self.materials.insert(material_path, hashes);
        self
    }

    pub fn add_product(mut self, material_path: VirtualTargetPath) -> Self {
        let file = File::open(material_path.to_string()).unwrap();
        let mut reader = BufReader::new(file);
        let (_length, hashes) = crypto::calculate_hashes(&mut reader,
                &[crypto::HashAlgorithm::Sha256]).unwrap();
        self.products.insert(material_path, hashes);
        self
    }

    /// Set the products for this metadata 
    pub fn env(mut self, env: BTreeMap<String, String>) -> Self {
        self.env = env;
        self
    }

    /// Set the products for this metadata 
    pub fn byproducts(mut self, byproducts: BTreeMap<String, String>) -> Self {
        self.byproducts = byproducts;
        self
    }

    pub fn build(self) -> Result<LinkMetadata> {
        LinkMetadata::new(self.name, self.materials, self.products, 
            self.env, self.byproducts)
    }

      /// Construct a new `SignedMetadata<D, LinkMetadata>`.
    pub fn signed<D>(self, private_key: &PrivateKey) -> Result<SignedMetadata<D, LinkMetadata>>
    where
        D: DataInterchange,
    {
        SignedMetadata::new(&self.build()?, private_key)
    }
}

/// link metadata
#[derive(Debug, Clone, PartialEq)]
pub struct LinkMetadata {
    name: String,
    materials: BTreeMap<VirtualTargetPath, TargetDescription>,
    products: BTreeMap<VirtualTargetPath, TargetDescription>,
    env: BTreeMap<String, String>,
    byproducts: BTreeMap<String, String>,
}

impl LinkMetadata {
    /// Create new `LinkMetadata`.
    pub fn new(
        name: String,
        materials: BTreeMap<VirtualTargetPath, TargetDescription>,
        products: BTreeMap<VirtualTargetPath, TargetDescription>,
        env: BTreeMap<String, String>,
        byproducts: BTreeMap<String, String>,
    ) -> Result<Self> {

        Ok(LinkMetadata {
            //Role: Role::Link,
            name,
            materials,
            products,
            env,
            byproducts
        })
    }


    // The step this link is associated to
    pub fn name(&self) -> &String {
        &self.name
    }

    // The materials used as inputs
    pub fn materials(&self) -> &BTreeMap<VirtualTargetPath, TargetDescription> {
        &self.materials
    }

    // The products used as inputs
    pub fn products(&self) -> &BTreeMap<VirtualTargetPath, TargetDescription> {
        &self.products
    }

    // The Environment where things were built
    pub fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    // The Environment where things were built
    pub fn byproducts(&self) -> &BTreeMap<String, String> {
        &self.byproducts
    }
}

impl Metadata for LinkMetadata {
    const ROLE: Role = Role::Link;

    fn version(&self) -> u32 {
        0u32
    }
}

impl Serialize for LinkMetadata {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        shims::Link::from(self)
            .map_err(|e| SerializeError::custom(format!("{:?}", e)))?
            .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for LinkMetadata {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::Link = Deserialize::deserialize(de)?;
        intermediate
            .try_into()
            .map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}


/// Wrapper for the Virtual path to a target.
#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize)]
pub struct VirtualTargetPath(String);

impl VirtualTargetPath {
    /// Create a new `VirtualTargetPath` from a `String`.
    ///
    /// ```
    /// # use tuf::metadata::VirtualTargetPath;
    /// assert!(VirtualTargetPath::new("foo".into()).is_ok());
    /// assert!(VirtualTargetPath::new("/foo".into()).is_err());
    /// assert!(VirtualTargetPath::new("../foo".into()).is_err());
    /// assert!(VirtualTargetPath::new("foo/..".into()).is_err());
    /// assert!(VirtualTargetPath::new("foo/../bar".into()).is_err());
    /// assert!(VirtualTargetPath::new("..foo".into()).is_ok());
    /// assert!(VirtualTargetPath::new("foo/..bar".into()).is_ok());
    /// assert!(VirtualTargetPath::new("foo/bar..".into()).is_ok());
    /// ```
    pub fn new(path: String) -> Result<Self> {
        safe_path(&path)?;
        Ok(VirtualTargetPath(path))
    }

    /// Split `VirtualTargetPath` into components that can be joined to create URL paths, Unix
    /// paths, or Windows paths.
    ///
    /// ```
    /// # use tuf::metadata::VirtualTargetPath;
    /// let path = VirtualTargetPath::new("foo/bar".into()).unwrap();
    /// assert_eq!(path.components(), ["foo".to_string(), "bar".to_string()]);
    /// ```
    pub fn components(&self) -> Vec<String> {
        self.0.split('/').map(|s| s.to_string()).collect()
    }

    /// Return whether this path is the child of another path.
    ///
    /// ```
    /// # use tuf::metadata::VirtualTargetPath;
    /// let path1 = VirtualTargetPath::new("foo".into()).unwrap();
    /// let path2 = VirtualTargetPath::new("foo/bar".into()).unwrap();
    /// assert!(!path2.is_child(&path1));
    ///
    /// let path1 = VirtualTargetPath::new("foo/".into()).unwrap();
    /// let path2 = VirtualTargetPath::new("foo/bar".into()).unwrap();
    /// assert!(path2.is_child(&path1));
    ///
    /// let path2 = VirtualTargetPath::new("foo/bar/baz".into()).unwrap();
    /// assert!(path2.is_child(&path1));
    ///
    /// let path2 = VirtualTargetPath::new("wat".into()).unwrap();
    /// assert!(!path2.is_child(&path1))
    /// ```
    pub fn is_child(&self, parent: &Self) -> bool {
        if !parent.0.ends_with('/') {
            return false;
        }

        self.0.starts_with(&parent.0)
    }

    /// Whether or not the current target is available at the end of the given chain of target
    /// paths. For the chain to be valid, each target path in a group must be a child of of all
    /// previous groups.
    // TODO this is hideous and uses way too much clone/heap but I think recursively,
    // so here we are
    pub fn matches_chain(&self, parents: &[HashSet<VirtualTargetPath>]) -> bool {
        if parents.is_empty() {
            return false;
        }
        if parents.len() == 1 {
            return parents[0].iter().any(|p| p == self || self.is_child(p));
        }

        let new = parents[1..]
            .iter()
            .map(|group| {
                group
                    .iter()
                    .filter(|parent| {
                        parents[0]
                            .iter()
                            .any(|p| parent.is_child(p) || parent == &p)
                    })
                    .cloned()
                    .collect::<HashSet<_>>()
            })
            .collect::<Vec<_>>();
        self.matches_chain(&*new)
    }

    /// The string value of the path.
    pub fn value(&self) -> &str {
        &self.0
    }
}

impl ToString for VirtualTargetPath {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl<'de> Deserialize<'de> for VirtualTargetPath {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        VirtualTargetPath::new(s).map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

/// Wrapper for the real path to a target.
#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize)]
pub struct TargetPath(String);

impl TargetPath {
    /// Create a new `TargetPath`.
    pub fn new(path: String) -> Result<Self> {
        safe_path(&path)?;
        Ok(TargetPath(path))
    }

    /// Split `TargetPath` into components that can be joined to create URL paths, Unix paths, or
    /// Windows paths.
    ///
    /// ```
    /// # use tuf::metadata::TargetPath;
    /// let path = TargetPath::new("foo/bar".into()).unwrap();
    /// assert_eq!(path.components(), ["foo".to_string(), "bar".to_string()]);
    /// ```
    pub fn components(&self) -> Vec<String> {
        self.0.split('/').map(|s| s.to_string()).collect()
    }

    /// The string value of the path.
    pub fn value(&self) -> &str {
        &self.0
    }

    /// Prefix the target path with a hash value to support TUF spec 5.5.2.
    pub fn with_hash_prefix(&self, hash: &HashValue) -> Result<TargetPath> {
        let mut components = self.components();

        // The unwrap here is safe because we checked in `safe_path` that the path is not empty.
        let file_name = components.pop().unwrap();

        components.push(format!("{}.{}", hash, file_name));

        TargetPath::new(components.join("/"))
    }
}

/// Description of a target, used in verification.
pub type TargetDescription = HashMap<HashAlgorithm, HashValue>;
