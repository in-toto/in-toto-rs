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
    /// The root role.
    #[serde(rename = "root")]
    Root,
    /// The timestamp role.
    #[serde(rename = "timestamp")]
    Timestamp,
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
    /// assert!(Role::Root.fuzzy_matches_path(&MetadataPath::from_role(&Role::Root)));
    /// assert!(Role::Timestamp.fuzzy_matches_path(&MetadataPath::from_role(&Role::Timestamp)));
    ///
    /// assert!(!Role::Root.fuzzy_matches_path(&MetadataPath::new("wat").unwrap()));
    /// ```
    pub fn fuzzy_matches_path(&self, path: &MetadataPath) -> bool {
        match *self {
            Role::Root if &path.0 == "root" => true,
            Role::Timestamp if &path.0 == "timestamp" => true,
            Role::Root if &path.0 == "link" => true,
            //Role::Layout if &path.0 == "layout" => true,
            _ => false,
        }
    }

    /// Return the name of the role.
    pub fn name(&self) -> &'static str {
        match *self {
            Role::Root => "root",
            Role::Timestamp => "timestamp",
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

/// Enum used for addressing versioned TUF metadata.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum MetadataVersion {
    /// The metadata is unversioned. This is the latest version of the metadata.
    None,
    /// The metadata is addressed by a specific version number.
    Number(u32),
    /// The metadata is addressed by a hash prefix. Used with TUF's consistent snapshot feature.
    Hash(HashValue),
}

impl MetadataVersion {
    /// Converts this struct into the string used for addressing metadata.
    pub fn prefix(&self) -> String {
        match *self {
            MetadataVersion::None => String::new(),
            MetadataVersion::Number(ref x) => format!("{}.", x),
            MetadataVersion::Hash(ref v) => format!("{}.", v),
        }
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

    /// Parse the version number of this metadata without verifying signatures.
    ///
    /// This operation is generally unsafe to do with metadata obtained from an untrusted source,
    /// but rolling forward to the most recent root.json requires using the version number of the
    /// latest root.json.
    pub(crate) fn parse_version_untrusted(&self) -> Result<u32> {
        #[derive(Deserialize)]
        pub struct MetadataVersion {
            version: u32,
        }

        let meta: MetadataVersion = D::deserialize(&self.metadata)?;
        Ok(meta.version)
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

/// Helper to construct `RootMetadata`.
pub struct RootMetadataBuilder {
    version: u32,
    keys: HashMap<KeyId, PublicKey>,
    root_threshold: u32,
    root_key_ids: Vec<KeyId>,
    timestamp_threshold: u32,
    timestamp_key_ids: Vec<KeyId>,
}

impl RootMetadataBuilder {
    /// Create a new `RootMetadataBuilder`. It defaults to:
    ///
    /// * version: 1,
    /// * role thresholds: 1
    pub fn new() -> Self {
        RootMetadataBuilder {
            version: 1,
            keys: HashMap::new(),
            root_threshold: 1,
            root_key_ids: Vec::new(),
            timestamp_threshold: 1,
            timestamp_key_ids: Vec::new(),
        }
    }

    /// Set the version number for this metadata.
    pub fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    /// Set the root threshold.
    pub fn root_threshold(mut self, threshold: u32) -> Self {
        self.root_threshold = threshold;
        self
    }

    /// Add a root public key.
    pub fn root_key(mut self, public_key: PublicKey) -> Self {
        let key_id = public_key.key_id().clone();
        self.keys.insert(key_id.clone(), public_key);
        self.root_key_ids.push(key_id);
        self
    }

    /// Set the timestamp threshold.
    pub fn timestamp_threshold(mut self, threshold: u32) -> Self {
        self.timestamp_threshold = threshold;
        self
    }

    /// Add a timestamp public key.
    pub fn timestamp_key(mut self, public_key: PublicKey) -> Self {
        let key_id = public_key.key_id().clone();
        self.keys.insert(key_id.clone(), public_key);
        self.timestamp_key_ids.push(key_id);
        self
    }

    /// Construct a new `RootMetadata`.
    pub fn build(self) -> Result<RootMetadata> {
        RootMetadata::new(
            self.version,
            self.keys,
            RoleDefinition::new(self.root_threshold, self.root_key_ids)?,
            RoleDefinition::new(self.timestamp_threshold, self.timestamp_key_ids)?,
        )
    }

    /// Construct a new `SignedMetadata<D, RootMetadata>`.
    pub fn signed<D>(self, private_key: &PrivateKey) -> Result<SignedMetadata<D, RootMetadata>>
    where
        D: DataInterchange,
    {
        SignedMetadata::new(&self.build()?, private_key)
    }
}

impl Default for RootMetadataBuilder {
    fn default() -> Self {
        RootMetadataBuilder::new()
    }
}

impl From<RootMetadata> for RootMetadataBuilder {
    fn from(metadata: RootMetadata) -> Self {
        RootMetadataBuilder {
            version: metadata.version,
            keys: metadata.keys,
            root_threshold: metadata.root.threshold,
            root_key_ids: metadata.root.key_ids,
            timestamp_threshold: metadata.timestamp.threshold,
            timestamp_key_ids: metadata.timestamp.key_ids,
        }
    }
}

/// Metadata for the root role.
#[derive(Debug, Clone, PartialEq)]
pub struct RootMetadata {
    version: u32,
    keys: HashMap<KeyId, PublicKey>,
    root: RoleDefinition,
    timestamp: RoleDefinition,
}

impl RootMetadata {
    /// Create new `RootMetadata`.
    pub fn new(
        version: u32,
        keys: HashMap<KeyId, PublicKey>,
        root: RoleDefinition,
        timestamp: RoleDefinition,
    ) -> Result<Self> {
        if version < 1 {
            return Err(Error::IllegalArgument(format!(
                "Metadata version must be greater than zero. Found: {}",
                version
            )));
        }

        Ok(RootMetadata {
            version,
            keys,
            root,
            timestamp,
        })
    }

    /// An immutable reference to the map of trusted keys.
    pub fn keys(&self) -> &HashMap<KeyId, PublicKey> {
        &self.keys
    }

    /// An immutable reference to the root role's definition.
    pub fn root(&self) -> &RoleDefinition {
        &self.root
    }

    /// An immutable reference to the timestamp role's definition.
    pub fn timestamp(&self) -> &RoleDefinition {
        &self.timestamp
    }
}

impl Metadata for RootMetadata {
    const ROLE: Role = Role::Root;

    fn version(&self) -> u32 {
        self.version
    }

}

impl Serialize for RootMetadata {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let m = shims::RootMetadata::from(self)
            .map_err(|e| SerializeError::custom(format!("{:?}", e)))?;
        m.serialize(ser)
    }
}

impl<'de> Deserialize<'de> for RootMetadata {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::RootMetadata = Deserialize::deserialize(de)?;
        intermediate
            .try_into()
            .map_err(|e| DeserializeError::custom(format!("{:?}", e)))
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
    /// assert_eq!(MetadataPath::from_role(&Role::Root),
    ///            MetadataPath::new("root").unwrap());
    /// assert_eq!(MetadataPath::from_role(&Role::Targets),
    ///            MetadataPath::new("targets").unwrap());
    /// assert_eq!(MetadataPath::from_role(&Role::Timestamp),
    ///            MetadataPath::new("timestamp").unwrap());
    /// ```
    pub fn from_role(role: &Role) -> Self {
        Self::new(format!("{}", role)).unwrap()
    }

    /// Split `MetadataPath` into components that can be joined to create URL paths, Unix paths, or
    /// Windows paths.
    ///
    /// ```
    /// # use tuf::crypto::HashValue;
    /// # use tuf::interchange::Json;
    /// # use tuf::metadata::{MetadataPath, MetadataVersion};
    /// #
    /// let path = MetadataPath::new("foo/bar").unwrap();
    /// assert_eq!(path.components::<Json>(&MetadataVersion::None),
    ///            ["foo".to_string(), "bar.json".to_string()]);
    /// assert_eq!(path.components::<Json>(&MetadataVersion::Number(1)),
    ///            ["foo".to_string(), "1.bar.json".to_string()]);
    /// assert_eq!(path.components::<Json>(
    ///                 &MetadataVersion::Hash(HashValue::new(vec![0x69, 0xb7, 0x1d]))),
    ///            ["foo".to_string(), "69b71d.bar.json".to_string()]);
    /// ```
    pub fn components<D>(&self, version: &MetadataVersion) -> Vec<String>
    where
        D: DataInterchange,
    {
        let mut buf: Vec<String> = self.0.split('/').map(|s| s.to_string()).collect();
        let len = buf.len();
        buf[len - 1] = format!("{}{}.{}", version.prefix(), buf[len - 1], D::extension());
        buf
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


///---
/// Helper to construct `TimestampMetadata`.
pub struct TimestampMetadataBuilder {
    version: u32,
}

impl TimestampMetadataBuilder {

    /// Set the version number for this metadata.
    pub fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    /// Construct a new `TimestampMetadata`.
    pub fn build(self) -> Result<TimestampMetadata> {
        TimestampMetadata::new(self.version)
    }

    /// Construct a new `SignedMetadata<D, TimestampMetadata>`.
    pub fn signed<D>(self, private_key: &PrivateKey) -> Result<SignedMetadata<D, TimestampMetadata>>
    where
        D: DataInterchange,
    {
        SignedMetadata::new(&self.build()?, private_key)
    }
}

/// Metadata for the timestamp role.
#[derive(Debug, Clone, PartialEq)]
pub struct TimestampMetadata {
    version: u32,
}

impl TimestampMetadata {
    /// Create new `TimestampMetadata`.
    pub fn new(
        version: u32,
    ) -> Result<Self> {
        if version < 1 {
            return Err(Error::IllegalArgument(format!(
                "Metadata version must be greater than zero. Found: {}",
                version
            )));
        }

        Ok(TimestampMetadata {
            version,
        })
    }
}

impl Metadata for TimestampMetadata {
    const ROLE: Role = Role::Timestamp;

    fn version(&self) -> u32 {
        self.version
    }

}

impl Serialize for TimestampMetadata {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        shims::TimestampMetadata::from(self)
            .map_err(|e| SerializeError::custom(format!("{:?}", e)))?
            .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for TimestampMetadata {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::TimestampMetadata = Deserialize::deserialize(de)?;
        intermediate
            .try_into()
            .map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

/// Description of a piece of metadata, used in verification.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MetadataDescription {
    version: u32,
    length: usize,
    hashes: HashMap<HashAlgorithm, HashValue>,
}

impl MetadataDescription {
    /// Create a `MetadataDescription` from a given reader. Size and hashes will be calculated.
    pub fn from_reader<R: Read>(
        read: R,
        version: u32,
        hash_algs: &[HashAlgorithm],
    ) -> Result<Self> {
        if version < 1 {
            return Err(Error::IllegalArgument(
                "Version must be greater than zero".into(),
            ));
        }

        let (length, hashes) = crypto::calculate_hashes(read, hash_algs)?;

        if length > ::std::usize::MAX as u64 {
            return Err(Error::IllegalArgument(
                "Calculated length exceeded usize".into(),
            ));
        }

        Ok(MetadataDescription {
            version,
            length: length as usize,
            hashes,
        })
    }

    /// Create a new `MetadataDescription`.
    pub fn new(
        version: u32,
        length: usize,
        hashes: HashMap<HashAlgorithm, HashValue>,
    ) -> Result<Self> {
        if version < 1 {
            return Err(Error::IllegalArgument(format!(
                "Metadata version must be greater than zero. Found: {}",
                version
            )));
        }

        if hashes.is_empty() {
            return Err(Error::IllegalArgument(
                "Cannot have empty set of hashes".into(),
            ));
        }

        Ok(MetadataDescription {
            version,
            length,
            hashes,
        })
    }

    /// The version of the described metadata.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The length of the described metadata.
    pub fn length(&self) -> usize {
        self.length
    }

    /// An immutable reference to the hashes of the described metadata.
    pub fn hashes(&self) -> &HashMap<HashAlgorithm, HashValue> {
        &self.hashes
    }
}

impl<'de> Deserialize<'de> for MetadataDescription {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::MetadataDescription = Deserialize::deserialize(de)?;
        intermediate
            .try_into()
            .map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}


/// Wrapper for the virtual path to a target.
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
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactHash {
    hashes: HashMap<HashAlgorithm, HashValue>,
}

impl ArtifactHash {
    /// Create a new `ArtifactHash`.
    ///
    /// Note: Creating this manually could lead to errors, and the `from_reader` method is
    /// preferred.
    pub fn new(
        hashes: HashMap<HashAlgorithm, HashValue>,
    ) -> Result<Self> {
        if hashes.is_empty() {
            return Err(Error::IllegalArgument(
                "Cannot have empty set of hashes".into(),
            ));
        }

        Ok(ArtifactHash {
            hashes,
        })
    }

    /// Read the from the given reader and calculate the length and hash values.
    ///
    /// ```
    /// use data_encoding::BASE64URL;
    /// use in_toto::crypto::{HashAlgorithm,HashValue};
    /// use in_toto::metadata::ArtifactHash;
    ///
    /// fn main() {
    ///     let bytes: &[u8] = b"it was a pleasure to burn";
    ///
    ///     let target_description = ArtifactHash::from_reader(
    ///         bytes,
    ///         &[HashAlgorithm::Sha256, HashAlgorithm::Sha512],
    ///     ).unwrap();
    ///
    ///     let s = "Rd9zlbzrdWfeL7gnIEi05X-Yv2TCpy4qqZM1N72ZWQs=";
    ///     let sha256 = HashValue::new(BASE64URL.decode(s.as_bytes()).unwrap());
    ///
    ///     let s ="tuIxwKybYdvJpWuUj6dubvpwhkAozWB6hMJIRzqn2jOUdtDTBg381brV4K\
    ///         BU1zKP8GShoJuXEtCf5NkDTCEJgQ==";
    ///     let sha512 = HashValue::new(BASE64URL.decode(s.as_bytes()).unwrap());
    ///
    ///     assert_eq!(target_description.hashes().get(&HashAlgorithm::Sha256), Some(&sha256));
    ///     assert_eq!(target_description.hashes().get(&HashAlgorithm::Sha512), Some(&sha512));
    /// }
    /// ```
    pub fn from_reader<R>(read: R, hash_algs: &[HashAlgorithm]) -> Result<Self>
    where
        R: Read,
    {
        let (_length, hashes) = crypto::calculate_hashes(read, hash_algs)?;
        Ok(ArtifactHash {
            hashes,
        })
    }

    /// An immutable reference to the list of calculated hashes.
    pub fn hashes(&self) -> &HashMap<HashAlgorithm, HashValue> {
        &self.hashes
    }
}

impl Serialize for ArtifactHash {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        shims::ArtifactHash::from(self).serialize(ser)
    }
}

/// Description of a target, used in verification.
#[derive(Debug, Clone, PartialEq)]
pub struct TargetDescription {
    hashes: HashMap<HashAlgorithm, HashValue>,
}

impl TargetDescription {
    /// Create a new `TargetDescription`.
    ///
    /// Note: Creating this manually could lead to errors, and the `from_reader` method is
    /// preferred.
    pub fn new(
        hashes: HashMap<HashAlgorithm, HashValue>,
    ) -> Result<Self> {
        if hashes.is_empty() {
            return Err(Error::IllegalArgument(
                "Cannot have empty set of hashes".into(),
            ));
        }

        Ok(TargetDescription {
            hashes,
        })
    }

    /// Read the from the given reader and calculate the length and hash values.
    ///
    /// ```
    /// use data_encoding::BASE64URL;
    /// use in_toto::crypto::{HashAlgorithm,HashValue};
    /// use in_toto::metadata::TargetDescription;
    ///
    /// fn main() {
    ///     let bytes: &[u8] = b"it was a pleasure to burn";
    ///
    ///     let target_description = TargetDescription::from_reader(
    ///         bytes,
    ///         &[HashAlgorithm::Sha256, HashAlgorithm::Sha512],
    ///     ).unwrap();
    ///
    ///     let s = "Rd9zlbzrdWfeL7gnIEi05X-Yv2TCpy4qqZM1N72ZWQs=";
    ///     let sha256 = HashValue::new(BASE64URL.decode(s.as_bytes()).unwrap());
    ///
    ///     let s ="tuIxwKybYdvJpWuUj6dubvpwhkAozWB6hMJIRzqn2jOUdtDTBg381brV4K\
    ///         BU1zKP8GShoJuXEtCf5NkDTCEJgQ==";
    ///     let sha512 = HashValue::new(BASE64URL.decode(s.as_bytes()).unwrap());
    ///
    ///     assert_eq!(target_description.length(), bytes.len() as u64);
    ///     assert_eq!(target_description.hashes().get(&HashAlgorithm::Sha256), Some(&sha256));
    ///     assert_eq!(target_description.hashes().get(&HashAlgorithm::Sha512), Some(&sha512));
    /// }
    /// ```
    pub fn from_reader<R>(read: R, hash_algs: &[HashAlgorithm]) -> Result<Self>
    where
        R: Read,
    {
        let (_length, hashes) = crypto::calculate_hashes(read, hash_algs)?;
        Ok(TargetDescription {
            hashes,
        })
    }

    /// Read the from the given reader and custom metadata and calculate the length and hash
    /// values.
    ///
    /// ```
    /// use data_encoding::BASE64URL;
    /// use serde_json::Value;
    /// use std::collections::HashMap;
    /// use in_toto::crypto::{HashAlgorithm,HashValue};
    /// use in_toto::metadata::TargetDescription;
    ///
    /// fn main() {
    ///     let bytes: &[u8] = b"it was a pleasure to burn";
    ///
    ///     let mut custom = HashMap::new();
    ///
    ///     let target_description = TargetDescription::from_reader_with_custom(
    ///         bytes,
    ///         &[HashAlgorithm::Sha256, HashAlgorithm::Sha512],
    ///     ).unwrap();
    ///
    ///     let s = "Rd9zlbzrdWfeL7gnIEi05X-Yv2TCpy4qqZM1N72ZWQs=";
    ///     let sha256 = HashValue::new(BASE64URL.decode(s.as_bytes()).unwrap());
    ///
    ///     let s ="tuIxwKybYdvJpWuUj6dubvpwhkAozWB6hMJIRzqn2jOUdtDTBg381brV4K\
    ///         BU1zKP8GShoJuXEtCf5NkDTCEJgQ==";
    ///     let sha512 = HashValue::new(BASE64URL.decode(s.as_bytes()).unwrap());
    ///
    ///     assert_eq!(target_description.hashes().get(&HashAlgorithm::Sha256), Some(&sha256));
    ///     assert_eq!(target_description.hashes().get(&HashAlgorithm::Sha512), Some(&sha512));
    /// }
    /// ```
    pub fn from_reader_with_custom<R>(
        read: R,
        hash_algs: &[HashAlgorithm],
    ) -> Result<Self>
    where
        R: Read,
    {
        let (_length, hashes) = crypto::calculate_hashes(read, hash_algs)?;
        Ok(TargetDescription {
            hashes,
        })
    }

    /// An immutable reference to the list of calculated hashes.
    pub fn hashes(&self) -> &HashMap<HashAlgorithm, HashValue> {
        &self.hashes
    }
}

impl Serialize for TargetDescription {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        shims::TargetDescription::from(self).serialize(ser)
    }
}

impl<'de> Deserialize<'de> for TargetDescription {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::TargetDescription = Deserialize::deserialize(de)?;
        intermediate
            .try_into()
            .map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::SignatureScheme;
    use crate::interchange::Json;
    use chrono::prelude::*;
    use maplit::{hashmap, hashset};
    use matches::assert_matches;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use std::str::FromStr;

    const ED25519_1_PK8: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-1.pk8.der");
    const ED25519_2_PK8: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-2.pk8.der");
    const ED25519_3_PK8: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-3.pk8.der");
    const ED25519_4_PK8: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-4.pk8.der");

    #[test]
    fn no_pardir_in_target_path() {
        let bad_paths = &[
            "..",
            "../some/path",
            "../some/path/",
            "some/../path",
            "some/../path/..",
        ];

        for path in bad_paths.iter() {
            assert!(safe_path(*path).is_err());
            assert!(TargetPath::new(path.to_string()).is_err());
            assert!(MetadataPath::new(path.to_string()).is_err());
            assert!(VirtualTargetPath::new(path.to_string()).is_err());
        }
    }

    #[test]
    fn path_matches_chain() {
        let test_cases: &[(bool, &str, &[&[&str]])] = &[
            // simplest case
            (true, "foo", &[&["foo"]]),
            // is a dir
            (false, "foo", &[&["foo/"]]),
            // target not in last position
            (false, "foo", &[&["foo"], &["bar"]]),
            // target nested
            (true, "foo/bar", &[&["foo/"], &["foo/bar"]]),
            // target illegally nested
            (false, "foo/bar", &[&["baz/"], &["foo/bar"]]),
            // target illegally deeply nested
            (
                false,
                "foo/bar/baz",
                &[&["foo/"], &["foo/quux/"], &["foo/bar/baz"]],
            ),
            // empty
            (false, "foo", &[&[]]),
            // empty 2
            (false, "foo", &[&[], &["foo"]]),
            // empty 3
            (false, "foo", &[&["foo"], &[]]),
        ];

        for case in test_cases {
            let expected = case.0;
            let target = VirtualTargetPath::new(case.1.into()).unwrap();
            let parents = case
                .2
                .iter()
                .map(|group| {
                    group
                        .iter()
                        .map(|p| VirtualTargetPath::new(p.to_string()).unwrap())
                        .collect::<HashSet<_>>()
                })
                .collect::<Vec<_>>();
            println!(
                "CASE: expect: {} path: {:?} parents: {:?}",
                expected, target, parents
            );
            assert_eq!(target.matches_chain(&parents), expected);
        }
    }

    #[test]
    fn serde_target_path() {
        let s = "foo/bar";
        let t = serde_json::from_str::<VirtualTargetPath>(&format!("\"{}\"", s)).unwrap();
        assert_eq!(t.to_string().as_str(), s);
        assert_eq!(serde_json::to_value(t).unwrap(), json!("foo/bar"));
    }

    #[test]
    fn serde_metadata_path() {
        let s = "foo/bar";
        let m = serde_json::from_str::<MetadataPath>(&format!("\"{}\"", s)).unwrap();
        assert_eq!(m.to_string().as_str(), s);
        assert_eq!(serde_json::to_value(m).unwrap(), json!("foo/bar"));
    }

    #[test]
    fn serde_target_description() {
        let s: &[u8] = b"from water does all life begin";
        let description = TargetDescription::from_reader(s, &[HashAlgorithm::Sha256]).unwrap();
        let jsn_str = serde_json::to_string(&description).unwrap();
        let jsn = json!({
            "length": 30,
            "hashes": {
                "sha256": "fc5d745c712bc86ea9a31264dac0c956eeb53857f677eed05829\
                    bb71013cae18",
            },
        });
        let parsed_str: TargetDescription = serde_json::from_str(&jsn_str).unwrap();
        let parsed_jsn: TargetDescription = serde_json::from_value(jsn).unwrap();
        assert_eq!(parsed_str, parsed_jsn);
    }

    #[test]
    fn serde_role_definition() {
        // keyid ordering must be preserved.
        let keyids = vec![
            KeyId::from_str("40e35e8f6003ab90d104710cf88901edab931597401f91c19eeb366060ab3d53")
                .unwrap(),
            KeyId::from_str("01892c662c8cd79fab20edec21de1dcb8b75d9353103face7fe086ff5c0098e4")
                .unwrap(),
            KeyId::from_str("4750eaf6878740780d6f97b12dbad079fb012bec88c78de2c380add56d3f51db")
                .unwrap(),
        ];
        let role_def = RoleDefinition::new(3, keyids).unwrap();
        let jsn = json!({
            "threshold": 3,
            "keyids": [
                "40e35e8f6003ab90d104710cf88901edab931597401f91c19eeb366060ab3d53",
                "01892c662c8cd79fab20edec21de1dcb8b75d9353103face7fe086ff5c0098e4",
                "4750eaf6878740780d6f97b12dbad079fb012bec88c78de2c380add56d3f51db",
            ],
        });
        let encoded = serde_json::to_value(&role_def).unwrap();
        assert_eq!(encoded, jsn);
        let decoded: RoleDefinition = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, role_def);
    }

    #[test]
    fn serde_invalid_role_definitions() {
        let jsn = json!({
            "threshold": 0,
            "keyids": [
                "01892c662c8cd79fab20edec21de1dcb8b75d9353103face7fe086ff5c0098e4",
                "4750eaf6878740780d6f97b12dbad079fb012bec88c78de2c380add56d3f51db",
            ],
        });
        assert!(serde_json::from_value::<RoleDefinition>(jsn).is_err());

        let jsn = json!({
            "threshold": -1,
            "keyids": [
                "01892c662c8cd79fab20edec21de1dcb8b75d9353103face7fe086ff5c0098e4",
                "4750eaf6878740780d6f97b12dbad079fb012bec88c78de2c380add56d3f51db",
            ],
        });
        assert!(serde_json::from_value::<RoleDefinition>(jsn).is_err());
    }

    #[test]
    fn serde_root_metadata() {
        let root_key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap();
        let snapshot_key = PrivateKey::from_pkcs8(ED25519_2_PK8, SignatureScheme::Ed25519).unwrap();
        let targets_key = PrivateKey::from_pkcs8(ED25519_3_PK8, SignatureScheme::Ed25519).unwrap();
        let timestamp_key =
            PrivateKey::from_pkcs8(ED25519_4_PK8, SignatureScheme::Ed25519).unwrap();

        let root = RootMetadataBuilder::new()
            .root_key(root_key.public().clone())
            .snapshot_key(snapshot_key.public().clone())
            .targets_key(targets_key.public().clone())
            .timestamp_key(timestamp_key.public().clone())
            .build()
            .unwrap();

        let jsn = json!({
            "_type": "root",
            "spec_version": "1.0",
            "version": 1,
            "consistent_snapshot": false,
            "keys": {
                "09557ed63f91b5b95917d46f66c63ea79bdaef1b008ba823808bca849f1d18a1": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyid_hash_algorithms": ["sha256", "sha512"],
                    "keyval": {
                        "public": "1410ae3053aa70bbfa98428a879d64d3002a3578f7dfaaeb1cb0764e860f7e0b",
                    },
                },
                "40e35e8f6003ab90d104710cf88901edab931597401f91c19eeb366060ab3d53": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyid_hash_algorithms": ["sha256", "sha512"],
                    "keyval": {
                        "public": "166376c90a7f717d027056272f361c252fb050bed1a067ff2089a0302fbab73d",
                    },
                },
                "a9f3ebc9b138762563a9c27b6edd439959e559709babd123e8d449ba2c18c61a": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyid_hash_algorithms": ["sha256", "sha512"],
                    "keyval": {
                        "public": "eb8ac26b5c9ef0279e3be3e82262a93bce16fe58ee422500d38caf461c65a3b6",
                    },
                },
                "fd7b7741686fa44903f1e4b61d7db869939f402b4acedc044767922c7d309983": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyid_hash_algorithms": ["sha256", "sha512"],
                    "keyval": {
                        "public": "68d9ecb387371005a8eb8e60105305c34356a8fcd859d7fef3cc228bf2b2b3b2",
                    },
                }
            },
            "roles": {
                "root": {
                    "threshold": 1,
                    "keyids": ["a9f3ebc9b138762563a9c27b6edd439959e559709babd123e8d449ba2c18c61a"],
                },
                "snapshot": {
                    "threshold": 1,
                    "keyids": ["fd7b7741686fa44903f1e4b61d7db869939f402b4acedc044767922c7d309983"],
                },
                "targets": {
                    "threshold": 1,
                    "keyids": ["40e35e8f6003ab90d104710cf88901edab931597401f91c19eeb366060ab3d53"],
                },
                "timestamp": {
                    "threshold": 1,
                    "keyids": ["09557ed63f91b5b95917d46f66c63ea79bdaef1b008ba823808bca849f1d18a1"],
                },
            },
        });

        let encoded = serde_json::to_value(&root).unwrap();
        assert_eq!(encoded, jsn);
        let decoded: RootMetadata = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, root);
    }

    fn jsn_root_metadata_without_keyid_hash_algos() -> serde_json::Value {
        json!({
            "_type": "root",
            "spec_version": "1.0",
            "version": 1,
            "consistent_snapshot": false,
            "keys": {
                "12435b260b6172bd750aeb102f54a347c56b109e0524ab1f144593c07af66356": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {
                        "public": "68d9ecb387371005a8eb8e60105305c34356a8fcd859d7fef3cc228bf2b2b3b2",
                    },
                },
                "3af6b427c05274532231760f39d81212fdf8ac1a9f8fddf12722623ccec02fec": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {
                        "public": "1410ae3053aa70bbfa98428a879d64d3002a3578f7dfaaeb1cb0764e860f7e0b",
                    },
                },
                "b9c336828063cf4fe5348e9fe2d86827c7b3104a76b1f4484a56bbef1ef08cfb": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {
                        "public": "166376c90a7f717d027056272f361c252fb050bed1a067ff2089a0302fbab73d",
                    },
                },
                "e0294a3f17cc8563c3ed5fceb3bd8d3f6bfeeaca499b5c9572729ae015566554": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {
                        "public": "eb8ac26b5c9ef0279e3be3e82262a93bce16fe58ee422500d38caf461c65a3b6",
                    },
                }
            },
            "roles": {
                "root": {
                    "threshold": 1,
                    "keyids": ["e0294a3f17cc8563c3ed5fceb3bd8d3f6bfeeaca499b5c9572729ae015566554"],
                },
                "snapshot": {
                    "threshold": 1,
                    "keyids": ["12435b260b6172bd750aeb102f54a347c56b109e0524ab1f144593c07af66356"],
                },
                "targets": {
                    "threshold": 1,
                    "keyids": ["b9c336828063cf4fe5348e9fe2d86827c7b3104a76b1f4484a56bbef1ef08cfb"],
                },
                "timestamp": {
                    "threshold": 1,
                    "keyids": ["3af6b427c05274532231760f39d81212fdf8ac1a9f8fddf12722623ccec02fec"],
                },
            },
        })
    }

    #[test]
    fn de_ser_root_metadata_without_keyid_hash_algorithms() {
        let jsn = jsn_root_metadata_without_keyid_hash_algos();
        let decoded: RootMetadata = serde_json::from_value(jsn.clone()).unwrap();
        let encoded = serde_json::to_value(decoded).unwrap();

        assert_eq!(jsn, encoded);
    }

    #[test]
    fn de_ser_root_metadata_wrong_key_id() {
        let jsn = jsn_root_metadata_without_keyid_hash_algos();
        let mut jsn_str = str::from_utf8(&Json::canonicalize(&jsn).unwrap())
            .unwrap()
            .to_owned();
        // Replace the key id to something else.
        jsn_str = jsn_str.replace(
            "12435b260b6172bd750aeb102f54a347c56b109e0524ab1f144593c07af66356",
            "00435b260b6172bd750aeb102f54a347c56b109e0524ab1f144593c07af66356",
        );
        let decoded: RootMetadata = serde_json::from_str(&jsn_str).unwrap();
        assert_eq!(3, decoded.keys.len());
    }

    #[test]
    fn sign_and_verify_root_metadata() {
        let jsn = jsn_root_metadata_without_keyid_hash_algos();
        let root_key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap();
        let decoded: RootMetadata = serde_json::from_value(jsn).unwrap();

        let signed: SignedMetadata<crate::interchange::cjson::Json, _> =
            SignedMetadata::new(&decoded, &root_key).unwrap();
        signed.verify(1, &[root_key.public().clone()]).unwrap();
    }

    #[test]
    fn verify_signed_serialized_root_metadata() {
        let jsn = json!({
            "signatures": [{
                "keyid": "a9f3ebc9b138762563a9c27b6edd439959e559709babd123e8d449ba2c18c61a",
                "sig": "c4ba838e0d3f783716393a4d691f568f840733ff488bb79ac68287e97e0b31d63fcef392dbc978e878c2103ba231905af634cc651d6f0e63a35782d051ac6e00"
            }],
            "signed": jsn_root_metadata_without_keyid_hash_algos()
        });
        let root_key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap();
        let decoded: SignedMetadata<crate::interchange::cjson::Json, RootMetadata> =
            serde_json::from_value(jsn).unwrap();

        decoded.verify(1, &[root_key.public().clone()]).unwrap();
    }

    #[test]
    fn verify_signed_serialized_root_metadata_with_duplicate_sig() {
        let jsn = json!({
            "signatures": [{
                "keyid": "a9f3ebc9b138762563a9c27b6edd439959e559709babd123e8d449ba2c18c61a",
                "sig": "c4ba838e0d3f783716393a4d691f568f840733ff488bb79ac68287e97e0b31d63fcef392dbc978e878c2103ba231905af634cc651d6f0e63a35782d051ac6e00"
            },
            {
                "keyid": "a9f3ebc9b138762563a9c27b6edd439959e559709babd123e8d449ba2c18c61a",
                "sig": "c4ba838e0d3f783716393a4d691f568f840733ff488bb79ac68287e97e0b31d63fcef392dbc978e878c2103ba231905af634cc651d6f0e63a35782d051ac6e00"
            }],
            "signed": jsn_root_metadata_without_keyid_hash_algos()
        });
        let root_key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap();
        let decoded: SignedMetadata<crate::interchange::cjson::Json, RootMetadata> =
            serde_json::from_value(jsn).unwrap();
        assert_matches!(
            decoded.verify(2, &[root_key.public().clone()]),
            Err(Error::VerificationFailure(_))
        );
        decoded.verify(1, &[root_key.public().clone()]).unwrap();
    }

    fn verify_signature_with_unknown_fields<M>(mut metadata: serde_json::Value)
    where
        M: Metadata,
    {
        let key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap();

        let mut standard = SignedMetadataBuilder::<Json, M>::from_raw_metadata(metadata.clone())
            .unwrap()
            .sign(&key)
            .unwrap()
            .build()
            .to_raw()
            .unwrap()
            .parse()
            .unwrap();

        metadata.as_object_mut().unwrap().insert(
            "custom".into(),
            json!({
                "metadata": ["please", "sign", "me"],
                "this-too": 42,
            }),
        );
        let mut custom = SignedMetadataBuilder::<Json, M>::from_raw_metadata(metadata)
            .unwrap()
            .sign(&key)
            .unwrap()
            .build()
            .to_raw()
            .unwrap()
            .parse()
            .unwrap();

        // Ensure the signatures are valid as-is.
        assert_matches!(standard.verify(1, std::iter::once(key.public())), Ok(_));
        assert_matches!(custom.verify(1, std::iter::once(key.public())), Ok(_));

        // But not if the metadata was signed with custom fields and they are now missing or
        // unexpected new fields appear.
        std::mem::swap(&mut standard.metadata, &mut custom.metadata);
        assert_matches!(
            standard.verify(1, std::iter::once(key.public())),
            Err(Error::VerificationFailure(_))
        );
        assert_matches!(
            custom.verify(1, std::iter::once(key.public())),
            Err(Error::VerificationFailure(_))
        );
    }

    #[test]
    fn unknown_fields_included_in_root_metadata_signature() {
        verify_signature_with_unknown_fields::<RootMetadata>(
            jsn_root_metadata_without_keyid_hash_algos(),
        );
    }

    #[test]
    fn unknown_fields_included_in_timestamp_metadata_signature() {
        verify_signature_with_unknown_fields::<TimestampMetadata>(make_timestamp());
    }

    #[test]
    fn unknown_fields_included_in_snapshot_metadata_signature() {
        verify_signature_with_unknown_fields::<SnapshotMetadata>(make_snapshot());
    }

    #[test]
    fn unknown_fields_included_in_targets_metadata_signature() {
        verify_signature_with_unknown_fields::<TargetsMetadata>(make_targets());
    }

    #[test]
    fn serde_timestamp_metadata() {
        let description = MetadataDescription::new(
            1,
            100,
            hashmap! { HashAlgorithm::Sha256 => HashValue::new(vec![]) },
        )
        .unwrap();

        let timestamp = TimestampMetadataBuilder::from_metadata_description(description)
            .build()
            .unwrap();

        let jsn = json!({
            "_type": "timestamp",
            "spec_version": "1.0",
            "version": 1,
            "meta": {
                "snapshot.json": {
                    "version": 1,
                    "length": 100,
                    "hashes": {
                        "sha256": "",
                    },
                },
            }
        });

        let encoded = serde_json::to_value(&timestamp).unwrap();
        assert_eq!(encoded, jsn);
        let decoded: TimestampMetadata = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, timestamp);
    }

    #[test]
    fn serde_timestamp_metadata_missing_snapshot() {
        let jsn = json!({
            "_type": "timestamp",
            "spec_version": "1.0",
            "version": 1,
            "meta": {}
        });

        assert_matches!(
            serde_json::from_value::<TimestampMetadata>(jsn),
            Err(ref err) if err.to_string() == "missing field `snapshot.json`"
        );
    }

    #[test]
    fn serde_timestamp_metadata_extra_metadata() {
        let jsn = json!({
            "_type": "timestamp",
            "spec_version": "1.0",
            "version": 1,
            "meta": {
                "snapshot.json": {
                    "version": 1,
                    "length": 100,
                    "hashes": {
                        "sha256": "",
                    },
                },
                "targets.json": {
                    "version": 1,
                    "length": 100,
                    "hashes": {
                        "sha256": "",
                    },
                },
            }
        });

        assert_matches!(
            serde_json::from_value::<TimestampMetadata>(jsn),
            Err(ref err) if err.to_string() ==
            "unknown field `targets.json`, expected `snapshot.json`"
        );
    }

    #[test]
    fn serde_snapshot_metadata() {
        let snapshot = SnapshotMetadataBuilder::new()
            .insert_metadata_description(
                MetadataPath::new("targets").unwrap(),
                MetadataDescription::new(
                    1,
                    100,
                    hashmap! { HashAlgorithm::Sha256 => HashValue::new(vec![]) },
                )
                .unwrap(),
            )
            .build()
            .unwrap();

        let jsn = json!({
            "_type": "snapshot",
            "spec_version": "1.0",
            "version": 1,
            "meta": {
                "targets.json": {
                    "version": 1,
                    "length": 100,
                    "hashes": {
                        "sha256": "",
                    },
                },
            },
        });

        let encoded = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(encoded, jsn);
        let decoded: SnapshotMetadata = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, snapshot);
    }

    #[test]
    fn serde_targets_metadata() {
        let targets = TargetsMetadataBuilder::new()
            .insert_target_description(
                VirtualTargetPath::new("foo".into()).unwrap(),
                TargetDescription::from_reader(&b"foo"[..], &[HashAlgorithm::Sha256]).unwrap(),
            )
            .insert_target_description(
                VirtualTargetPath::new("bar".into()).unwrap(),
                TargetDescription::from_reader_with_custom(
                    &b"foo"[..],
                    &[HashAlgorithm::Sha256],
                    HashMap::new(),
                )
                .unwrap(),
            )
            .insert_target_description(
                VirtualTargetPath::new("baz".into()).unwrap(),
                TargetDescription::from_reader_with_custom(
                    &b"foo"[..],
                    &[HashAlgorithm::Sha256],
                    hashmap! {
                        "foo".into() => 1.into(),
                        "bar".into() => "baz".into(),
                    },
                )
                .unwrap(),
            )
            .build()
            .unwrap();

        let jsn = json!({
            "_type": "targets",
            "spec_version": "1.0",
            "version": 1,
            "targets": {
                "foo": {
                    "length": 3,
                    "hashes": {
                        "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483\
                            bfa0f98a5e886266e7ae",
                    },
                },
                "bar": {
                    "length": 3,
                    "hashes": {
                        "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483\
                            bfa0f98a5e886266e7ae",
                    },
                    "custom": {},
                },
                "baz": {
                    "length": 3,
                    "hashes": {
                        "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483\
                            bfa0f98a5e886266e7ae",
                    },
                    "custom": {
                        "foo": 1,
                        "bar": "baz",
                    },
                },
            },
        });

        let encoded = serde_json::to_value(&targets).unwrap();
        assert_eq!(encoded, jsn);
        let decoded: TargetsMetadata = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, targets);
    }

    #[test]
    fn serde_signed_metadata() {
        let snapshot = SnapshotMetadataBuilder::new()
            .insert_metadata_description(
                MetadataPath::new("targets").unwrap(),
                MetadataDescription::new(
                    1,
                    100,
                    hashmap! { HashAlgorithm::Sha256 => HashValue::new(vec![]) },
                )
                .unwrap(),
            )
            .build()
            .unwrap();

        let key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap();

        let signed = SignedMetadata::<Json, _>::new(&snapshot, &key).unwrap();

        let jsn = json!({
            "signatures": [
                {
                    "keyid": "a9f3ebc9b138762563a9c27b6edd439959e559709babd123e8d449ba2c18c61a",
                    "sig": "ea48ddc7b3ea614b394e508eb8722100f94ff1a4e3aac3af09d\
                        a0dada4f878431e8ac26160833405ec239924dfe62edf605fee8294\
                        c49b4acade55c76e817602",
                }
            ],
            "signed": {
                "_type": "snapshot",
                "spec_version": "1.0",
                "version": 1,
                "meta": {
                    "targets.json": {
                        "version": 1,
                        "length": 100,
                        "hashes": {
                            "sha256": "",
                        },
                    },
                },
            },
        });

        let encoded = serde_json::to_value(&signed).unwrap();
        assert_eq!(encoded, jsn, "{:#?} != {:#?}", encoded, jsn);
        let decoded: SignedMetadata<Json, SnapshotMetadata> =
            serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, signed);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //
    // Here there be test cases about what metadata is allowed to be parsed wherein we do all sorts
    // of naughty things and make sure the parsers puke appropriately.
    //                                   ______________
    //                             ,===:'.,            `-._
    //                                  `:.`---.__         `-._
    //                                    `:.     `--.         `.
    //                                      \.        `.         `.
    //                              (,,(,    \.         `.   ____,-`.,
    //                           (,'     `/   \.   ,--.___`.'
    //                       ,  ,'  ,--.  `,   \.;'         `
    //                        `{o, {    \  :    \;
    //                          |,,'    /  /    //
    //                          j;;    /  ,' ,-//.    ,---.      ,
    //                          \;'   /  ,' /  _  \  /  _  \   ,'/
    //                                \   `'  / \  `'  / \  `.' /
    //                                 `.___,'   `.__,'   `.__,'
    //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    // TODO test for mismatched ed25519/rsa keys/schemes

    fn make_root() -> serde_json::Value {
        let root_key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap();
        let snapshot_key = PrivateKey::from_pkcs8(ED25519_2_PK8, SignatureScheme::Ed25519).unwrap();
        let targets_key = PrivateKey::from_pkcs8(ED25519_3_PK8, SignatureScheme::Ed25519).unwrap();
        let timestamp_key =
            PrivateKey::from_pkcs8(ED25519_4_PK8, SignatureScheme::Ed25519).unwrap();

        let root = RootMetadataBuilder::new()
            .root_key(root_key.public().clone())
            .snapshot_key(snapshot_key.public().clone())
            .targets_key(targets_key.public().clone())
            .timestamp_key(timestamp_key.public().clone())
            .build()
            .unwrap();

        serde_json::to_value(&root).unwrap()
    }

    fn make_snapshot() -> serde_json::Value {
        let snapshot = SnapshotMetadataBuilder::new()
            .build()
            .unwrap();

        serde_json::to_value(&snapshot).unwrap()
    }

    fn make_timestamp() -> serde_json::Value {
        let description =
            MetadataDescription::from_reader(&[][..], 1, &[HashAlgorithm::Sha256]).unwrap();

        let timestamp = TimestampMetadataBuilder::from_metadata_description(description)
            .build()
            .unwrap();

        serde_json::to_value(&timestamp).unwrap()
    }

    fn make_targets() -> serde_json::Value {
        let targets =
            TargetsMetadata::new(1, Utc.ymd(2038, 1, 1).and_hms(0, 0, 0), hashmap!(), None)
                .unwrap();

        serde_json::to_value(&targets).unwrap()
    }

    fn set_version(value: &mut serde_json::Value, version: i64) {
        match value.as_object_mut() {
            Some(obj) => {
                let _ = obj.insert("version".into(), json!(version));
            }
            None => panic!(),
        }
    }

    // Refuse to deserialize root metadata if the version is not > 0
    #[test]
    fn deserialize_json_root_illegal_version() {
        let mut root_json = make_root();
        set_version(&mut root_json, 0);
        assert!(serde_json::from_value::<RootMetadata>(root_json.clone()).is_err());

        let mut root_json = make_root();
        set_version(&mut root_json, -1);
        assert!(serde_json::from_value::<RootMetadata>(root_json).is_err());
    }

    // Refuse to deserialize root metadata if it contains duplicate keys
    #[test]
    fn deserialize_json_root_duplicate_keys() {
        let root_json = r#"{
            "_type": "root",
            "spec_version": "1.0",
            "version": 1,
            "consistent_snapshot": false,
            "keys": {
                "09557ed63f91b5b95917d46f66c63ea79bdaef1b008ba823808bca849f1d18a1": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {
                        "public": "1410ae3053aa70bbfa98428a879d64d3002a3578f7dfaaeb1cb0764e860f7e0b"
                    }
                },
                "09557ed63f91b5b95917d46f66c63ea79bdaef1b008ba823808bca849f1d18a1": {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {
                        "public": "166376c90a7f717d027056272f361c252fb050bed1a067ff2089a0302fbab73d"
                    }
                }
            },
            "roles": {
                "root": {
                    "threshold": 1,
                    "keyids": ["09557ed63f91b5b95917d46f66c63ea79bdaef1b008ba823808bca849f1d18a1"]
                },
                "snapshot": {
                    "threshold": 1,
                    "keyids": ["09557ed63f91b5b95917d46f66c63ea79bdaef1b008ba823808bca849f1d18a1"]
                },
                "targets": {
                    "threshold": 1,
                    "keyids": ["09557ed63f91b5b95917d46f66c63ea79bdaef1b008ba823808bca849f1d18a1"]
                },
                "timestamp": {
                    "threshold": 1,
                    "keyids": ["09557ed63f91b5b95917d46f66c63ea79bdaef1b008ba823808bca849f1d18a1"]
                }
            }
        }"#;
        match serde_json::from_str::<RootMetadata>(root_json) {
            Err(ref err) if err.is_data() => {
                assert!(
                    err.to_string().starts_with("Cannot have duplicate keys"),
                    "unexpected err: {:?}",
                    err
                );
            }
            result => panic!("unexpected result: {:?}", result),
        }
    }

    fn set_threshold(value: &mut serde_json::Value, threshold: i32) {
        match value.as_object_mut() {
            Some(obj) => {
                let _ = obj.insert("threshold".into(), json!(threshold));
            }
            None => panic!(),
        }
    }

    // Refuse to deserialize role definitions with illegal thresholds
    #[test]
    fn deserialize_json_role_definition_illegal_threshold() {
        let role_def = RoleDefinition::new(
            1,
            vec![
                PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519)
                    .unwrap()
                    .key_id()
                    .clone(),
            ],
        )
        .unwrap();

        let mut jsn = serde_json::to_value(&role_def).unwrap();
        set_threshold(&mut jsn, 0);
        assert!(serde_json::from_value::<RoleDefinition>(jsn).is_err());

        let mut jsn = serde_json::to_value(&role_def).unwrap();
        set_threshold(&mut jsn, -1);
        assert!(serde_json::from_value::<RoleDefinition>(jsn).is_err());

        let role_def = RoleDefinition::new(
            2,
            vec![
                PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519)
                    .unwrap()
                    .key_id()
                    .clone(),
                PrivateKey::from_pkcs8(ED25519_2_PK8, SignatureScheme::Ed25519)
                    .unwrap()
                    .key_id()
                    .clone(),
            ],
        )
        .unwrap();

        let mut jsn = serde_json::to_value(&role_def).unwrap();
        set_threshold(&mut jsn, 3);
        assert!(serde_json::from_value::<RoleDefinition>(jsn).is_err());
    }

    // Refuse to deserialize root metadata with wrong type field
    #[test]
    fn deserialize_json_root_bad_type() {
        let mut root = make_root();
        let _ = root
            .as_object_mut()
            .unwrap()
            .insert("_type".into(), json!("snapshot"));
        assert!(serde_json::from_value::<RootMetadata>(root).is_err());
    }

    // Refuse to deserialize root metadata with unknown spec version
    #[test]
    fn deserialize_json_root_bad_spec_version() {
        let mut root = make_root();
        let _ = root
            .as_object_mut()
            .unwrap()
            .insert("spec_version".into(), json!("0"));
        assert!(serde_json::from_value::<RootMetadata>(root).is_err());
    }

    // Refuse to deserialize role definitions with duplicated key ids
    #[test]
    fn deserialize_json_role_definition_duplicate_key_ids() {
        let key_id = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519)
            .unwrap()
            .key_id()
            .clone();
        let role_def = RoleDefinition::new(1, vec![key_id.clone()]).unwrap();
        let mut jsn = serde_json::to_value(&role_def).unwrap();

        match jsn.as_object_mut() {
            Some(obj) => match obj.get_mut("keyids").unwrap().as_array_mut() {
                Some(arr) => arr.push(json!(key_id)),
                None => panic!(),
            },
            None => panic!(),
        }

        assert!(serde_json::from_value::<RoleDefinition>(jsn).is_err());
    }

    // Refuse to deserialize snapshot metadata with illegal versions
    #[test]
    fn deserialize_json_snapshot_illegal_version() {
        let mut snapshot = make_snapshot();
        set_version(&mut snapshot, 0);
        assert!(serde_json::from_value::<SnapshotMetadata>(snapshot).is_err());

        let mut snapshot = make_snapshot();
        set_version(&mut snapshot, -1);
        assert!(serde_json::from_value::<SnapshotMetadata>(snapshot).is_err());
    }

    // Refuse to deserialize snapshot metadata with wrong type field
    #[test]
    fn deserialize_json_snapshot_bad_type() {
        let mut snapshot = make_snapshot();
        let _ = snapshot
            .as_object_mut()
            .unwrap()
            .insert("_type".into(), json!("root"));
        assert!(serde_json::from_value::<SnapshotMetadata>(snapshot).is_err());
    }

    // Refuse to deserialize snapshot metadata with unknown spec version
    #[test]
    fn deserialize_json_snapshot_spec_version() {
        let mut snapshot = make_snapshot();
        let _ = snapshot
            .as_object_mut()
            .unwrap()
            .insert("spec_version".into(), json!("0"));
        assert!(serde_json::from_value::<SnapshotMetadata>(snapshot).is_err());
    }

    // Refuse to deserialize snapshot metadata if it contains duplicate metadata
    #[test]
    fn deserialize_json_snapshot_duplicate_metadata() {
        let snapshot_json = r#"{
            "_type": "snapshot",
            "spec_version": "1.0",
            "version": 1,
            "meta": {
                "targets.json": {
                    "version": 1,
                    "length": 100,
                    "hashes": {
                        "sha256": ""
                    }
                },
                "targets.json": {
                    "version": 1,
                    "length": 100,
                    "hashes": {
                        "sha256": ""
                    }
                }
            }
        }"#;
        match serde_json::from_str::<SnapshotMetadata>(snapshot_json) {
            Err(ref err) if err.is_data() => {}
            result => panic!("unexpected result: {:?}", result),
        }
    }

    // Refuse to deserialize timestamp metadata with illegal versions
    #[test]
    fn deserialize_json_timestamp_illegal_version() {
        let mut timestamp = make_timestamp();
        set_version(&mut timestamp, 0);
        assert!(serde_json::from_value::<TimestampMetadata>(timestamp).is_err());

        let mut timestamp = make_timestamp();
        set_version(&mut timestamp, -1);
        assert!(serde_json::from_value::<TimestampMetadata>(timestamp).is_err());
    }

    // Refuse to deserialize timestamp metadata with wrong type field
    #[test]
    fn deserialize_json_timestamp_bad_type() {
        let mut timestamp = make_timestamp();
        let _ = timestamp
            .as_object_mut()
            .unwrap()
            .insert("_type".into(), json!("root"));
        assert!(serde_json::from_value::<TimestampMetadata>(timestamp).is_err());
    }

    // Refuse to deserialize timestamp metadata with unknown spec version
    #[test]
    fn deserialize_json_timestamp_bad_spec_version() {
        let mut timestamp = make_timestamp();
        let _ = timestamp
            .as_object_mut()
            .unwrap()
            .insert("spec_version".into(), json!("0"));
        assert!(serde_json::from_value::<TimestampMetadata>(timestamp).is_err());
    }

    // Refuse to deserialize timestamp metadata if it contains duplicate metadata
    #[test]
    fn deserialize_json_timestamp_duplicate_metadata() {
        let timestamp_json = r#"{
            "_type": "timestamp",
            "spec_version": "1.0",
            "version": 1,
            "meta": {
                "snapshot.json": {
                    "version": 1,
                    "length": 100,
                    "hashes": {
                        "sha256": ""
                    }
                },
                "snapshot.json": {
                    "version": 1,
                    "length": 100,
                    "hashes": {
                        "sha256": ""
                    }
                }
            }
        }"#;
        match serde_json::from_str::<TimestampMetadata>(timestamp_json) {
            Err(ref err) if err.is_data() => {}
            result => panic!("unexpected result: {:?}", result),
        }
    }

    // Refuse to deserialize targets metadata with illegal versions
    #[test]
    fn deserialize_json_targets_illegal_version() {
        let mut targets = make_targets();
        set_version(&mut targets, 0);
        assert!(serde_json::from_value::<TargetsMetadata>(targets).is_err());

        let mut targets = make_targets();
        set_version(&mut targets, -1);
        assert!(serde_json::from_value::<TargetsMetadata>(targets).is_err());
    }

    // Refuse to deserialize targets metadata with wrong type field
    #[test]
    fn deserialize_json_targets_bad_type() {
        let mut targets = make_targets();
        let _ = targets
            .as_object_mut()
            .unwrap()
            .insert("_type".into(), json!("root"));
        assert!(serde_json::from_value::<TargetsMetadata>(targets).is_err());
    }

    // Refuse to deserialize targets metadata with unknown spec version
    #[test]
    fn deserialize_json_targets_bad_spec_version() {
        let mut targets = make_targets();
        let _ = targets
            .as_object_mut()
            .unwrap()
            .insert("spec_version".into(), json!("0"));
        assert!(serde_json::from_value::<TargetsMetadata>(targets).is_err());
    }
}
