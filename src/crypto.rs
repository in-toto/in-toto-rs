//! Cryptographic structures and functions.

use data_encoding::HEXLOWER;
use derp::{self, Der, Tag};
use ring::digest::{self, SHA256, SHA512};
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaKeyPair, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_ASN1_SIGNING, ED25519, RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA512,
    RSA_PSS_SHA256, RSA_PSS_SHA512,
};
use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use serde::ser::{Error as SerializeError, Serialize, Serializer};
use serde_derive::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt::{self, Debug, Display};
use std::hash;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::Arc;
use untrusted::Input;

use crate::error::Error;
use crate::interchange::cjson::shims;
use crate::Result;

const HASH_ALG_PREFS: &[HashAlgorithm] = &[HashAlgorithm::Sha512, HashAlgorithm::Sha256];

/// 1.2.840.113549.1.1.1 rsaEncryption(PKCS #1)
const RSA_SPKI_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// 1.3.101.112 curveEd25519(EdDSA 25519 signature algorithm)
const ED25519_SPKI_OID: &[u8] = &[0x2b, 0x65, 0x70];

/// 1.2.840.10045.2.1 ecPublicKey (Elliptic Curve public key cryptography)
const ECC_SPKI_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/// The length of an ed25519 private key in bytes
const ED25519_PRIVATE_KEY_LENGTH: usize = 32;

/// The length of an ed25519 public key in bytes
const ED25519_PUBLIC_KEY_LENGTH: usize = 32;

/// The length of an ed25519 keypair in bytes
const ED25519_KEYPAIR_LENGTH: usize = ED25519_PRIVATE_KEY_LENGTH + ED25519_PUBLIC_KEY_LENGTH;

/// Pem header of a rsa private key
const PEM_PUBLIC_KEY: &str = "PUBLIC KEY";

fn python_sslib_compatibility_keyid_hash_algorithms() -> Option<Vec<String>> {
    Some(vec!["sha256".to_string(), "sha512".to_string()])
}

/// Given a map of hash algorithms and their values, get the prefered algorithm and the hash
/// calculated by it. Returns an `Err` if there is no match.
///
/// ```
/// use std::collections::HashMap;
/// use in_toto::crypto::{hash_preference, HashValue, HashAlgorithm};
///
/// let mut map = HashMap::new();
/// assert!(hash_preference(&map).is_err());
///
/// let _ = map.insert(HashAlgorithm::Sha512, HashValue::new(vec![0x00, 0x01]));
/// assert_eq!(hash_preference(&map).unwrap().0, &HashAlgorithm::Sha512);
///
/// let _ = map.insert(HashAlgorithm::Sha256, HashValue::new(vec![0x02, 0x03]));
/// assert_eq!(hash_preference(&map).unwrap().0, &HashAlgorithm::Sha512);
/// ```
pub fn hash_preference(
    hashes: &HashMap<HashAlgorithm, HashValue>,
) -> Result<(&'static HashAlgorithm, &HashValue)> {
    for alg in HASH_ALG_PREFS {
        match hashes.get(alg) {
            Some(v) => return Ok((alg, v)),
            None => continue,
        }
    }
    Err(Error::NoSupportedHashAlgorithm)
}

/// Calculate the size and hash digest from a given `Read`.
pub fn calculate_hashes<R: Read>(
    mut read: R,
    hash_algs: &[HashAlgorithm],
) -> Result<(u64, HashMap<HashAlgorithm, HashValue>)> {
    if hash_algs.is_empty() {
        return Err(Error::IllegalArgument(
            "Cannot provide empty set of hash algorithms".into(),
        ));
    }

    let mut size = 0;
    let mut hashes = HashMap::new();
    for alg in hash_algs {
        let _ = hashes.insert(alg, alg.digest_context()?);
    }

    let mut buf = vec![0; 1024];
    loop {
        match read.read(&mut buf) {
            Ok(read_bytes) => {
                if read_bytes == 0 {
                    break;
                }

                size += read_bytes as u64;

                for context in hashes.values_mut() {
                    context.update(&buf[0..read_bytes]);
                }
            }
            e @ Err(_) => e.map(|_| ())?,
        }
    }

    let hashes = hashes
        .drain()
        .map(|(k, v)| (k.clone(), HashValue::new(v.finish().as_ref().to_vec())))
        .collect();
    Ok((size, hashes))
}

fn shim_public_key(
    key_type: &KeyType,
    signature_scheme: &SignatureScheme,
    keyid_hash_algorithms: &Option<Vec<String>>,
    public_key: &[u8],
    private_key: bool,
    keyid: Option<&str>,
) -> Result<shims::PublicKey> {
    let key = match key_type {
        KeyType::Ed25519 => HEXLOWER.encode(public_key),
        KeyType::Rsa => {
            let contents = write_spki(public_key, key_type)?;
            let public_pem = pem::Pem::new(PEM_PUBLIC_KEY.to_string(), contents);
            pem::encode(&public_pem)
                .replace("\r\n", "\n")
                .trim()
                .to_string()
        }
        KeyType::Ecdsa => HEXLOWER.encode(public_key),
        KeyType::Unknown(inner) => {
            return Err(Error::UnknownKeyType(format!("content: {}", inner)))
        }
    };

    let private_key = private_key.then_some("");

    Ok(shims::PublicKey::new(
        key_type.clone(),
        signature_scheme.clone(),
        keyid_hash_algorithms.clone(),
        key,
        keyid,
        private_key,
    ))
}

/// Calculate unique key_id. This function will convert the der bytes
/// of the public key into PKIX-encoded pem bytes to keep consistent
/// with the python and golang version.
fn calculate_key_id(
    key_type: &KeyType,
    signature_scheme: &SignatureScheme,
    keyid_hash_algorithms: &Option<Vec<String>>,
    public_key: &[u8],
) -> Result<KeyId> {
    use crate::interchange::{DataInterchange, Json};

    let public_key = shim_public_key(
        key_type,
        signature_scheme,
        keyid_hash_algorithms,
        public_key,
        false,
        None,
    )?;
    let public_key = Json::canonicalize(&Json::serialize(&public_key)?)?;
    let public_key = String::from_utf8(public_key)
        .map_err(|e| Error::Encoding(format!("public key from bytes to string failed: {}", e,)))?
        .replace("\\n", "\n");
    let mut context = digest::Context::new(&SHA256);
    context.update(public_key.as_bytes());

    let key_id = HEXLOWER.encode(context.finish().as_ref());

    Ok(KeyId(key_id))
}

/// Wrapper type for public key's ID.
///
/// # Calculating
/// A `KeyId` is calculated as the hex digest of the SHA-256 hash of the canonical form of the
/// public key, or `hexdigest(sha256(cjson(public_key)))`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(String);

impl KeyId {
    /// Return the first 8 hex digits of the key id
    pub fn prefix(&self) -> String {
        assert!(self.0.len() >= 8);
        self.0[0..8].to_string()
    }
}

impl FromStr for KeyId {
    type Err = Error;

    /// Parse a key ID from a string.
    fn from_str(string: &str) -> Result<Self> {
        if string.len() != 64 {
            return Err(Error::IllegalArgument(
                "key ID must be 64 characters long".into(),
            ));
        }
        Ok(KeyId(string.to_owned()))
    }
}

impl Serialize for KeyId {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(ser)
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let string: String = Deserialize::deserialize(de)?;
        KeyId::from_str(&string).map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

/// Cryptographic signature schemes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureScheme {
    /// [Ed25519](https://ed25519.cr.yp.to/)
    #[serde(rename = "ed25519")]
    Ed25519,
    /// [RSASSA-PSS](https://tools.ietf.org/html/rfc5756) calculated over SHA256
    #[serde(rename = "rsassa-pss-sha256")]
    RsaSsaPssSha256,
    /// [RSASSA-PSS](https://tools.ietf.org/html/rfc5756) calculated over SHA512
    #[serde(rename = "rsassa-pss-sha512")]
    RsaSsaPssSha512,
    /// [ECDSA](https://www.rfc-editor.org/rfc/rfc5480) calculated over SHA256
    /// Also known as 'prime256v1', 'P-256', and 'sepc256r1').
    #[serde(rename = "ecdsa-sha2-nistp256")]
    EcdsaP256Sha256,
    /// Placeholder for an unknown scheme.
    Unknown(String),
}

/// Wrapper type for the value of a cryptographic signature.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureValue(#[serde(with = "crate::format_hex")] Vec<u8>);

impl SignatureValue {
    /// Create a new `SignatureValue` from the given bytes.
    ///
    /// Note: It is unlikely that you ever want to do this manually.
    pub fn new(bytes: Vec<u8>) -> Self {
        SignatureValue(bytes)
    }

    /// Create a new `SignatureValue` from the given hex string.
    ///
    /// Note: It is unlikely that you ever want to do this manually.
    pub fn from_hex(string: &str) -> Result<Self> {
        Ok(SignatureValue(HEXLOWER.decode(string.as_bytes())?))
    }

    /// Return the signature as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for SignatureValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("SignatureValue")
            .field(&HEXLOWER.encode(&self.0))
            .finish()
    }
}

/// Types of public keys.
#[derive(Clone, PartialEq, Debug, Eq, Hash)]
pub enum KeyType {
    /// [Ed25519](https://ed25519.cr.yp.to/)
    Ed25519,
    /// [RSA](https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29)
    Rsa,
    /// [ECDSA](https://www.rfc-editor.org/rfc/rfc5480)
    Ecdsa,
    /// Placeholder for an unknown key type.
    Unknown(String),
}

impl KeyType {
    pub fn from_oid(oid: &[u8]) -> Result<Self> {
        match oid {
            x if x == RSA_SPKI_OID => Ok(KeyType::Rsa),
            x if x == ED25519_SPKI_OID => Ok(KeyType::Ed25519),
            x if x == ECC_SPKI_OID => Ok(KeyType::Ecdsa),
            x => Err(Error::Encoding(format!(
                "Unknown OID: {}",
                x.iter().map(|b| format!("{:x}", b)).collect::<String>()
            ))),
        }
    }

    pub fn as_oid(&self) -> Result<&'static [u8]> {
        match *self {
            KeyType::Rsa => Ok(RSA_SPKI_OID),
            KeyType::Ed25519 => Ok(ED25519_SPKI_OID),
            KeyType::Ecdsa => Ok(ECC_SPKI_OID),
            KeyType::Unknown(ref s) => Err(Error::UnknownKeyType(s.clone())),
        }
    }
}

impl FromStr for KeyType {
    type Err = Error;

    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        match s {
            "ed25519" => Ok(KeyType::Ed25519),
            "rsa" => Ok(KeyType::Rsa),
            "ecdsa" => Ok(KeyType::Ecdsa),
            typ => Err(Error::Encoding(typ.into())),
        }
    }
}

impl ToString for KeyType {
    fn to_string(&self) -> String {
        match *self {
            KeyType::Ed25519 => "ed25519".to_string(),
            KeyType::Rsa => "rsa".to_string(),
            KeyType::Ecdsa => "ecdsa".to_string(),
            KeyType::Unknown(ref s) => s.to_string(),
        }
    }
}

impl Serialize for KeyType {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ser.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for KeyType {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let string: String = Deserialize::deserialize(de)?;
        string
            .parse()
            .map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

enum PrivateKeyType {
    Ed25519(Ed25519KeyPair),
    Rsa(Arc<RsaKeyPair>),
    Ecdsa(EcdsaKeyPair),
}

impl Debug for PrivateKeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match *self {
            PrivateKeyType::Ed25519(_) => "Ed25519",
            PrivateKeyType::Rsa(_) => "Rsa",
            PrivateKeyType::Ecdsa(_) => "Ecdsa",
        };
        f.debug_tuple(s).field(&"_").finish()
    }
}

/// A structure containing information about a private key.
pub struct PrivateKey {
    private: PrivateKeyType,
    public: PublicKey,
}

impl PrivateKey {
    /// Generate a new `PrivateKey` bytes in pkcs8 format.
    ///
    /// Note: For RSA keys, `openssl` needs to the on the `$PATH`.
    pub fn new(key_type: KeyType) -> Result<Vec<u8>> {
        match key_type {
            KeyType::Ed25519 => Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .map(|bytes| bytes.as_ref().to_vec())
                .map_err(|_| Error::Opaque("Failed to generate Ed25519 key".into())),
            KeyType::Rsa => Self::rsa_gen(),
            KeyType::Ecdsa => {
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                    .map(|bytes| bytes.as_ref().to_vec())
                    .map_err(|_| Error::Opaque("Failed to generate Ecdsa key".into()))
            }
            KeyType::Unknown(s) => Err(Error::IllegalArgument(format!("Unknown key type: {}", s))),
        }
    }

    /// Create a new `PrivateKey` from an ed25519 keypair, a 64 byte slice, where the first 32
    /// bytes are the ed25519 seed, and the second 32 bytes are the public key.
    pub fn from_ed25519(key: &[u8]) -> Result<Self> {
        Self::from_ed25519_with_keyid_hash_algorithms(key, None)
    }

    fn from_ed25519_with_keyid_hash_algorithms(
        key: &[u8],
        keyid_hash_algorithms: Option<Vec<String>>,
    ) -> Result<Self> {
        if key.len() != ED25519_KEYPAIR_LENGTH {
            return Err(Error::Encoding(
                "ed25519 private keys must be 64 bytes long".into(),
            ));
        }

        let (private_key_bytes, public_key_bytes) = key.split_at(ED25519_PRIVATE_KEY_LENGTH);

        let key = Ed25519KeyPair::from_seed_and_public_key(private_key_bytes, public_key_bytes)
            .map_err(|err| Error::Encoding(err.to_string()))?;

        let public = PublicKey::new(
            KeyType::Ed25519,
            SignatureScheme::Ed25519,
            keyid_hash_algorithms,
            key.public_key().as_ref().to_vec(),
        )?;
        let private = PrivateKeyType::Ed25519(key);

        Ok(PrivateKey { private, public })
    }

    /// Create a private key from PKCS#8v2 DER bytes.
    ///
    /// # Generating Keys
    ///
    /// ## Ed25519
    ///
    /// ```bash
    /// $ touch ed25519-private-key.pk8
    /// $ chmod 0600 ed25519-private-key.pk8
    /// ```
    ///
    /// ```no_run
    /// # use ring::rand::SystemRandom;
    /// # use ring::signature::Ed25519KeyPair;
    /// # use std::fs::File;
    /// # use std::io::Write;
    /// # fn main() {
    /// let mut file = File::open("ed25519-private-key.pk8").unwrap();
    /// let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    /// file.write_all(key.as_ref()).unwrap()
    /// # }
    /// ```
    ///
    /// ## RSA
    ///
    /// ```bash
    /// $ umask 077
    /// $ openssl genpkey -algorithm RSA \
    ///     -pkeyopt rsa_keygen_bits:4096 \
    ///     -pkeyopt rsa_keygen_pubexp:65537 | \
    ///     openssl pkcs8 -topk8 -nocrypt -outform der > rsa-4096-private-key.pk8
    /// ```
    ///
    /// ## Ecdsa
    ///
    /// ```bash
    /// $ openssl ecparam -name prime256v1 -genkey -noout -out ec.pem
    /// $ openssl pkcs8 -in ec.pem -outform der -out ec.pk8.der -topk8 -nocrypt
    /// ```
    pub fn from_pkcs8(der_key: &[u8], scheme: SignatureScheme) -> Result<Self> {
        let res = Self::ed25519_from_pkcs8(der_key);
        if res.is_ok() {
            if scheme != SignatureScheme::Ed25519 {
                return Err(Error::IllegalArgument(format!(
                    "Cannot use signature scheme {:?} with Ed25519 keys",
                    scheme,
                )));
            }
            return res;
        }

        let res = Self::rsa_from_pkcs8(der_key, scheme.clone());
        if res.is_ok() {
            return res;
        }

        let res = Self::ecdsa_from_pkcs8(der_key, scheme);
        if res.is_ok() {
            return res;
        }

        Err(Error::Opaque(
            "Key was not Ed25519, RSA, or ECDSA".to_string(),
        ))
    }

    fn ed25519_from_pkcs8(der_key: &[u8]) -> Result<Self> {
        Self::ed25519_from_pkcs8_with_keyid_hash_algorithms(
            der_key,
            python_sslib_compatibility_keyid_hash_algorithms(),
        )
    }

    fn ed25519_from_pkcs8_with_keyid_hash_algorithms(
        der_key: &[u8],
        keyid_hash_algorithms: Option<Vec<String>>,
    ) -> Result<Self> {
        let key = Ed25519KeyPair::from_pkcs8(der_key)
            .map_err(|_| Error::Encoding("Could not parse key as PKCS#8v2".into()))?;

        let public = PublicKey::new(
            KeyType::Ed25519,
            SignatureScheme::Ed25519,
            keyid_hash_algorithms,
            key.public_key().as_ref().to_vec(),
        )?;
        let private = PrivateKeyType::Ed25519(key);

        Ok(PrivateKey { private, public })
    }

    fn rsa_from_pkcs8(der_key: &[u8], scheme: SignatureScheme) -> Result<Self> {
        if let SignatureScheme::Ed25519 = scheme {
            return Err(Error::IllegalArgument(
                "RSA keys do not support the Ed25519 signing scheme".into(),
            ));
        }

        let key = RsaKeyPair::from_pkcs8(der_key)
            .map_err(|_| Error::Encoding("Could not parse key as PKCS#8v2".into()))?;

        if key.public_modulus_len() < 256 {
            return Err(Error::IllegalArgument(format!(
                "RSA public modulus must be 2048 or greater. Found {}",
                key.public_modulus_len() * 8
            )));
        }

        let pub_key = extract_rsa_pub_from_pkcs8(der_key)?;

        let public = PublicKey::new(
            KeyType::Rsa,
            scheme,
            python_sslib_compatibility_keyid_hash_algorithms(),
            pub_key,
        )?;
        let private = PrivateKeyType::Rsa(Arc::new(key));

        Ok(PrivateKey { private, public })
    }

    fn ecdsa_from_pkcs8(der_key: &[u8], scheme: SignatureScheme) -> Result<Self> {
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, der_key).unwrap();
        let public = PublicKey::new(
            KeyType::Ecdsa,
            scheme,
            python_sslib_compatibility_keyid_hash_algorithms(),
            key_pair.public_key().as_ref().to_vec(),
        )?;
        let private = PrivateKeyType::Ecdsa(key_pair);
        Ok(PrivateKey { private, public })
    }

    /// Sign a message.
    pub fn sign(&self, msg: &[u8]) -> Result<Signature> {
        let value = match (&self.private, &self.public.scheme) {
            (PrivateKeyType::Rsa(rsa), &SignatureScheme::RsaSsaPssSha256) => {
                let rng = SystemRandom::new();
                let mut buf = vec![0; rsa.public_modulus_len()];
                rsa.sign(&RSA_PSS_SHA256, &rng, msg, &mut buf)
                    .map_err(|_| Error::Opaque("Failed to sign message.".into()))?;
                SignatureValue(buf)
            }
            (PrivateKeyType::Rsa(rsa), &SignatureScheme::RsaSsaPssSha512) => {
                let rng = SystemRandom::new();
                let mut buf = vec![0; rsa.public_modulus_len()];
                rsa.sign(&RSA_PSS_SHA512, &rng, msg, &mut buf)
                    .map_err(|_| Error::Opaque("Failed to sign message.".into()))?;
                SignatureValue(buf)
            }
            (PrivateKeyType::Ed25519(ed), &SignatureScheme::Ed25519) => {
                SignatureValue(ed.sign(msg).as_ref().into())
            }
            (PrivateKeyType::Ecdsa(ec), &SignatureScheme::EcdsaP256Sha256) => {
                let rng = SystemRandom::new();
                let s = ec
                    .sign(&rng, msg)
                    .map_err(|_| Error::Opaque("Failed to sign message.".into()))?;
                SignatureValue(s.as_ref().into())
            }
            (k, s) => {
                return Err(Error::IllegalArgument(format!(
                    "Key {:?} can't be used with scheme {:?}",
                    k, s
                )));
            }
        };

        Ok(Signature {
            key_id: self.key_id().clone(),
            value,
        })
    }

    fn rsa_gen() -> Result<Vec<u8>> {
        let gen = Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:4096",
                "-pkeyopt",
                "rsa_keygen_pubexp:65537",
                "-outform",
                "der",
            ])
            .output()?;

        let mut pk8 = Command::new("openssl")
            .args([
                "pkcs8", "-inform", "der", "-topk8", "-nocrypt", "-outform", "der",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        match pk8.stdin {
            Some(ref mut stdin) => stdin.write_all(&gen.stdout)?,
            None => return Err(Error::Opaque("openssl has no stdin".into())),
        };

        Ok(pk8.wait_with_output()?.stdout)
    }

    /// Return the public component of the key.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Return the key ID of the public key.
    pub fn key_id(&self) -> &KeyId {
        &self.public.key_id
    }
}

/// A structure containing information about a public key.
#[derive(Clone, Debug)]
pub struct PublicKey {
    typ: KeyType,
    key_id: KeyId,
    scheme: SignatureScheme,
    keyid_hash_algorithms: Option<Vec<String>>,
    value: PublicKeyValue,
}

impl PublicKey {
    fn new(
        typ: KeyType,
        scheme: SignatureScheme,
        keyid_hash_algorithms: Option<Vec<String>>,
        value: Vec<u8>,
    ) -> Result<Self> {
        let key_id = calculate_key_id(&typ, &scheme, &keyid_hash_algorithms, &value)?;
        let value = PublicKeyValue(value);
        Ok(PublicKey {
            typ,
            key_id,
            scheme,
            keyid_hash_algorithms,
            value,
        })
    }

    /// Parse DER bytes as an SPKI key.
    ///
    /// See the documentation on `KeyValue` for more information on SPKI.
    pub fn from_spki(der_bytes: &[u8], scheme: SignatureScheme) -> Result<Self> {
        Self::from_spki_with_keyid_hash_algorithms(
            der_bytes,
            scheme,
            python_sslib_compatibility_keyid_hash_algorithms(),
        )
    }

    /// Parse PEM as an Subject Public Key Info (SPKI) key.
    ///
    /// See the documentation on `KeyValue` for more information on SPKI.
    pub fn from_pem_spki(pem: &str, scheme: SignatureScheme) -> Result<Self> {
        let der_bytes = pem::parse(pem).unwrap();
        Self::from_spki_with_keyid_hash_algorithms(
            der_bytes.contents(),
            scheme,
            python_sslib_compatibility_keyid_hash_algorithms(),
        )
    }

    /// Parse DER bytes as an SPKI key and the `keyid_hash_algorithms`.
    ///
    /// See the documentation on `KeyValue` for more information on SPKI.
    fn from_spki_with_keyid_hash_algorithms(
        der_bytes: &[u8],
        scheme: SignatureScheme,
        keyid_hash_algorithms: Option<Vec<String>>,
    ) -> Result<Self> {
        let input = Input::from(der_bytes);

        let (typ, value) = input.read_all(derp::Error::Read, |input| {
            derp::nested(input, Tag::Sequence, |input| {
                let typ = derp::nested(input, Tag::Sequence, |input| {
                    let typ = derp::expect_tag_and_get_value(input, Tag::Oid)?;

                    let typ = KeyType::from_oid(typ.as_slice_less_safe())
                        .map_err(|_| derp::Error::WrongValue)?;

                    if typ == KeyType::Ecdsa {
                        let _alg_oid = derp::expect_tag_and_get_value(input, Tag::Oid)?;
                    } else {
                        // for RSA / ed25519 this is null, so don't both parsing it
                        derp::read_null(input)?;
                    }
                    Ok(typ)
                })?;
                let value = derp::bit_string_with_no_unused_bits(input)?;
                Ok((typ, value.as_slice_less_safe().to_vec()))
            })
        })?;

        Self::new(typ, scheme, keyid_hash_algorithms, value)
    }

    /// Parse ED25519 bytes as a public key.
    pub fn from_ed25519<T: Into<Vec<u8>>>(bytes: T) -> Result<Self> {
        Self::from_ed25519_with_keyid_hash_algorithms(bytes, None)
    }

    /// Parse ED25519 bytes as a public key with a custom `keyid_hash_algorithms`.
    pub fn from_ed25519_with_keyid_hash_algorithms<T: Into<Vec<u8>>>(
        bytes: T,
        keyid_hash_algorithms: Option<Vec<String>>,
    ) -> Result<Self> {
        let bytes = bytes.into();
        if bytes.len() != 32 {
            return Err(Error::IllegalArgument(
                "ed25519 keys must be 32 bytes long".into(),
            ));
        }

        Self::new(
            KeyType::Ed25519,
            SignatureScheme::Ed25519,
            keyid_hash_algorithms,
            bytes,
        )
    }

    /// Parse Ecdsa bytes as a public key.
    pub fn from_ecdsa<T: Into<Vec<u8>>>(bytes: T) -> Result<Self> {
        Self::from_ecdsa_with_keyid_hash_algorithms(bytes, None)
    }

    /// Parse Ecdsa bytes as a public key with a custom `keyid_hash_algorithms`.
    pub fn from_ecdsa_with_keyid_hash_algorithms<T: Into<Vec<u8>>>(
        bytes: T,
        keyid_hash_algorithms: Option<Vec<String>>,
    ) -> Result<Self> {
        let bytes = bytes.into();
        Self::new(
            KeyType::Ecdsa,
            SignatureScheme::EcdsaP256Sha256,
            keyid_hash_algorithms,
            bytes,
        )
    }

    pub fn from_ecdsa_with_keyid_hash_algorithm<T: Into<Vec<u8>>>(
        der_bytes: T,
        scheme: SignatureScheme,
        keyid_hash_algorithms: Option<Vec<String>>,
    ) -> Result<Self> {
        let bytes = der_bytes.into();
        Self::new(KeyType::Ecdsa, scheme, keyid_hash_algorithms, bytes)
    }

    /// Write the public key as SPKI DER bytes.
    ///
    /// See the documentation on `KeyValue` for more information on SPKI.
    pub fn as_spki(&self) -> Result<Vec<u8>> {
        Ok(write_spki(&self.value.0, &self.typ)?)
    }

    /// An immutable reference to the key's type.
    pub fn typ(&self) -> &KeyType {
        &self.typ
    }

    /// An immutable referece to the key's authorized signing scheme.
    pub fn scheme(&self) -> &SignatureScheme {
        &self.scheme
    }

    /// An immutable reference to the key's ID.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// Return the public key as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.value.0
    }

    /// Use this key to verify a message with a signature.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        let alg: &dyn ring::signature::VerificationAlgorithm = match self.scheme {
            SignatureScheme::Ed25519 => &ED25519,
            SignatureScheme::RsaSsaPssSha256 => &RSA_PSS_2048_8192_SHA256,
            SignatureScheme::RsaSsaPssSha512 => &RSA_PSS_2048_8192_SHA512,
            SignatureScheme::EcdsaP256Sha256 => &ECDSA_P256_SHA256_ASN1,
            SignatureScheme::Unknown(ref s) => {
                return Err(Error::IllegalArgument(format!(
                    "Unknown signature scheme: {}",
                    s
                )));
            }
        };

        let key = ring::signature::UnparsedPublicKey::new(alg, &self.value.0);
        key.verify(msg, &sig.value.0)
            .map_err(|_| Error::BadSignature)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        // key_id is derived from these fields, so we ignore it.
        self.typ == other.typ
            && self.scheme == other.scheme
            && self.keyid_hash_algorithms == other.keyid_hash_algorithms
            && self.value == other.value
    }
}

impl Eq for PublicKey {}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key_id.cmp(&other.key_id)
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.key_id.cmp(&other.key_id))
    }
}

impl hash::Hash for PublicKey {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        // key_id is derived from these fields, so we ignore it.
        self.typ.hash(state);
        self.scheme.hash(state);
        self.keyid_hash_algorithms.hash(state);
        self.value.hash(state);
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let key = shim_public_key(
            &self.typ,
            &self.scheme,
            &self.keyid_hash_algorithms,
            &self.value.0,
            true,
            Some(&self.key_id.0),
        )
        .map_err(|e| SerializeError::custom(format!("Couldn't write key as SPKI: {:?}", e)))?;
        key.serialize(ser)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: shims::PublicKey = Deserialize::deserialize(de)?;

        let key = match intermediate.keytype() {
            KeyType::Ed25519 => {
                if intermediate.scheme() != &SignatureScheme::Ed25519 {
                    return Err(DeserializeError::custom(format!(
                        "ed25519 key type must be used with the ed25519 signature scheme, not {:?}",
                        intermediate.scheme()
                    )));
                }

                let bytes = HEXLOWER
                    .decode(intermediate.public_key().as_bytes())
                    .map_err(|e| {
                        DeserializeError::custom(format!("Couldn't parse key as HEX: {:?}", e))
                    })?;

                PublicKey::from_ed25519_with_keyid_hash_algorithms(
                    bytes,
                    intermediate.keyid_hash_algorithms().clone(),
                )
                .map_err(|e| {
                    DeserializeError::custom(format!("Couldn't parse key as ed25519: {:?}", e))
                })?
            }
            KeyType::Rsa => {
                let pub_pem = pem::parse(intermediate.public_key().as_bytes()).map_err(|e| {
                    DeserializeError::custom(format!("pem deserialize failed: {:?}", e))
                })?;

                PublicKey::from_spki_with_keyid_hash_algorithms(
                    pub_pem.contents(),
                    intermediate.scheme().clone(),
                    intermediate.keyid_hash_algorithms().clone(),
                )
                .map_err(|e| {
                    DeserializeError::custom(format!("Couldn't parse key as SPKI: {:?}", e))
                })?
            }
            KeyType::Ecdsa => {
                if intermediate.scheme() != &SignatureScheme::EcdsaP256Sha256 {
                    return Err(DeserializeError::custom(format!(
                        "ecdsa key type must be used with the ecdsa signature scheme, not {:?}",
                        intermediate.scheme()
                    )));
                }
                let bytes = HEXLOWER
                    .decode(intermediate.public_key().as_bytes())
                    .map_err(|e| {
                        DeserializeError::custom(format!("Couldn't parse key as HEX: {:?}", e))
                    })?;
                PublicKey::from_ecdsa_with_keyid_hash_algorithm(
                    bytes,
                    intermediate.scheme().clone(),
                    intermediate.keyid_hash_algorithms().clone(),
                )
                .map_err(|e| {
                    DeserializeError::custom(format!("Couldn't parse key as SPKI: {:?}", e))
                })?
            }
            KeyType::Unknown(inner) => {
                return Err(DeserializeError::custom(format!(
                    "Unknown key type, content: {}",
                    inner
                )))
            }
        };

        if intermediate.keytype() != &key.typ {
            return Err(DeserializeError::custom(format!(
                "Key type listed in the metadata did not match the type extrated \
                 from the key. {:?} vs. {:?}",
                intermediate.keytype(),
                key.typ,
            )));
        }

        Ok(key)
    }
}

#[derive(Clone, PartialEq, Hash, Eq)]
struct PublicKeyValue(Vec<u8>);

impl Debug for PublicKeyValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("PublicKeyValue")
            .field(&HEXLOWER.encode(&self.0))
            .finish()
    }
}

/// A structure that contains a `Signature` and associated data for verifying it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    #[serde(rename = "keyid")]
    key_id: KeyId,
    #[serde(rename = "sig")]
    value: SignatureValue,
}

impl Signature {
    /// An immutable reference to the `KeyId` of the key that produced the signature.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// An immutable reference to the `SignatureValue`.
    pub fn value(&self) -> &SignatureValue {
        &self.value
    }
}

/// The available hash algorithms.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// SHA256 as describe in [RFC-6234](https://tools.ietf.org/html/rfc6234)
    #[serde(rename = "sha256")]
    Sha256,
    /// SHA512 as describe in [RFC-6234](https://tools.ietf.org/html/rfc6234)
    #[serde(rename = "sha512")]
    Sha512,
    /// Placeholder for an unknown hash algorithm.
    Unknown(String),
}

impl HashAlgorithm {
    /// Create a new `digest::Context` suitable for computing the hash of some data using this hash
    /// algorithm.
    pub(crate) fn digest_context(&self) -> Result<digest::Context> {
        match self {
            HashAlgorithm::Sha256 => Ok(digest::Context::new(&SHA256)),
            HashAlgorithm::Sha512 => Ok(digest::Context::new(&SHA512)),
            HashAlgorithm::Unknown(ref s) => Err(Error::IllegalArgument(format!(
                "Unknown hash algorithm: {}",
                s
            ))),
        }
    }
    pub fn return_all() -> HashMap<String, HashAlgorithm> {
        let mut map = HashMap::new();
        map.insert(String::from("sha256"), HashAlgorithm::Sha256);
        map.insert(String::from("sha512"), HashAlgorithm::Sha512);
        map
    }
}

/// Wrapper for the value of a hash digest.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct HashValue(#[serde(with = "crate::format_hex")] Vec<u8>);

impl HashValue {
    /// Create a new `HashValue` from the given digest bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        HashValue(bytes)
    }

    /// An immutable reference to the bytes of the hash value.
    pub fn value(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("HashValue")
            .field(&HEXLOWER.encode(&self.0))
            .finish()
    }
}

impl Display for HashValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", HEXLOWER.encode(&self.0))
    }
}

fn write_spki(public: &[u8], key_type: &KeyType) -> ::std::result::Result<Vec<u8>, derp::Error> {
    let mut output = Vec::new();
    {
        let mut der = Der::new(&mut output);
        der.sequence(|der| {
            der.sequence(|der| match key_type.as_oid().ok() {
                Some(tag) => {
                    der.element(Tag::Oid, tag)?;
                    der.null()
                }
                None => Err(derp::Error::WrongValue),
            })?;
            der.bit_string(0, public)
        })?;
    }

    Ok(output)
}

fn extract_rsa_pub_from_pkcs8(der_key: &[u8]) -> ::std::result::Result<Vec<u8>, derp::Error> {
    let input = Input::from(der_key);
    input.read_all(derp::Error::Read, |input| {
        derp::nested(input, Tag::Sequence, |input| {
            if derp::small_nonnegative_integer(input)? != 0 {
                return Err(derp::Error::WrongValue);
            }

            derp::nested(input, Tag::Sequence, |input| {
                let actual_alg_id = derp::expect_tag_and_get_value(input, Tag::Oid)?;
                if actual_alg_id.as_slice_less_safe() != RSA_SPKI_OID {
                    return Err(derp::Error::WrongValue);
                }
                let _ = derp::expect_tag_and_get_value(input, Tag::Null)?;
                Ok(())
            })?;

            derp::nested(input, Tag::OctetString, |input| {
                derp::nested(input, Tag::Sequence, |input| {
                    if derp::small_nonnegative_integer(input)? != 0 {
                        return Err(derp::Error::WrongValue);
                    }

                    let n = derp::positive_integer(input)?;
                    let e = derp::positive_integer(input)?;
                    input.skip_to_end();
                    write_pkcs1(n.as_slice_less_safe(), e.as_slice_less_safe())
                })
            })
        })
    })
}

fn write_pkcs1(n: &[u8], e: &[u8]) -> ::std::result::Result<Vec<u8>, derp::Error> {
    let mut output = Vec::new();
    {
        let mut der = Der::new(&mut output);
        der.sequence(|der| {
            der.positive_integer(n)?;
            der.positive_integer(e)
        })?;
    }

    Ok(output)
}

#[cfg(test)]
mod test {
    use crate::models::Metablock;

    use super::*;
    use pretty_assertions::assert_eq;
    use serde_json::{self, json};
    use std::str;

    const RSA_2048_PK8: &'static [u8] = include_bytes!("../tests/rsa/rsa-2048.pk8.der");
    const RSA_2048_SPKI: &'static [u8] = include_bytes!("../tests/rsa/rsa-2048.spki.der");
    const RSA_2048_PKCS1: &'static [u8] = include_bytes!("../tests/rsa/rsa-2048.pkcs1.der");

    const RSA_4096_PK8: &'static [u8] = include_bytes!("../tests/rsa/rsa-4096.pk8.der");
    const RSA_4096_SPKI: &'static [u8] = include_bytes!("../tests/rsa/rsa-4096.spki.der");
    const RSA_4096_PKCS1: &'static [u8] = include_bytes!("../tests/rsa/rsa-4096.pkcs1.der");

    const ED25519_1_PRIVATE_KEY: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-1");
    const ED25519_1_PUBLIC_KEY: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-1.pub");
    const ED25519_1_PK8: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-1.pk8.der");
    const ED25519_1_SPKI: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-1.spki.der");
    const ED25519_2_PK8: &'static [u8] = include_bytes!("../tests/ed25519/ed25519-2.pk8.der");

    const ECDSA_PK8: &'static [u8] = include_bytes!("../tests/ecdsa/ec.pk8.der");
    const ECDSA_SPKI: &'static [u8] = include_bytes!("../tests/ecdsa/ec.spki.der");
    const ECDSA_PUBLIC_KEY: &'static [u8] = include_bytes!("../tests/ecdsa/ec.pub");

    const DEMO_KEY_ID: &str = "556caebdc0877eed53d419b60eddb1e57fa773e4e31d70698b588f3e9cc48b35";
    const DEMO_PUBLIC_KEY: &'static [u8] = include_bytes!("../tests/rsa/alice.pub");
    const DEMO_LAYOUT: &'static [u8] =
        include_bytes!("../tests/test_verifylib/workdir/root.layout");

    #[test]
    fn parse_public_rsa_2048_spki() {
        let key = PublicKey::from_spki(RSA_2048_SPKI, SignatureScheme::RsaSsaPssSha256).unwrap();
        assert_eq!(key.typ, KeyType::Rsa);
        assert_eq!(key.scheme, SignatureScheme::RsaSsaPssSha256);
    }

    #[test]
    fn parse_public_rsa_4096_spki() {
        let key = PublicKey::from_spki(RSA_4096_SPKI, SignatureScheme::RsaSsaPssSha256).unwrap();
        assert_eq!(key.typ, KeyType::Rsa);
        assert_eq!(key.scheme, SignatureScheme::RsaSsaPssSha256);
    }

    #[test]
    fn parse_public_ed25519_spki() {
        let key = PublicKey::from_spki(ED25519_1_SPKI, SignatureScheme::Ed25519).unwrap();
        assert_eq!(key.typ, KeyType::Ed25519);
        assert_eq!(key.scheme, SignatureScheme::Ed25519);
    }

    #[test]
    fn parse_public_ecdsa_spki() {
        let key = PublicKey::from_spki(ECDSA_SPKI, SignatureScheme::EcdsaP256Sha256).unwrap();
        assert_eq!(key.typ, KeyType::Ecdsa);
        assert_eq!(key.scheme, SignatureScheme::EcdsaP256Sha256);
    }

    #[test]
    fn parse_public_ed25519() {
        let key = PublicKey::from_ed25519(ED25519_1_PUBLIC_KEY).unwrap();
        assert_eq!(
            key.key_id(),
            &KeyId::from_str("e0294a3f17cc8563c3ed5fceb3bd8d3f6bfeeaca499b5c9572729ae015566554")
                .unwrap()
        );
        assert_eq!(key.typ, KeyType::Ed25519);
        assert_eq!(key.scheme, SignatureScheme::Ed25519);
    }

    #[test]
    fn parse_public_ecdsa() {
        let key = PublicKey::from_ecdsa(ECDSA_PUBLIC_KEY).unwrap();
        assert_eq!(
            key.key_id(),
            &KeyId::from_str("d23fafcd03bf36532580dbab48b54f53e280ccb119db5846cc6fbe094c612947")
                .unwrap()
        );
        assert_eq!(key.typ, KeyType::Ecdsa);
        assert_eq!(key.scheme, SignatureScheme::EcdsaP256Sha256);
    }

    #[test]
    fn parse_public_ed25519_without_keyid_hash_algo() {
        let key =
            PublicKey::from_ed25519_with_keyid_hash_algorithms(ED25519_1_PUBLIC_KEY, None).unwrap();
        assert_eq!(
            key.key_id(),
            &KeyId::from_str("e0294a3f17cc8563c3ed5fceb3bd8d3f6bfeeaca499b5c9572729ae015566554")
                .unwrap()
        );
        assert_eq!(key.typ, KeyType::Ed25519);
        assert_eq!(key.scheme, SignatureScheme::Ed25519);
    }

    #[test]
    fn parse_public_ed25519_with_keyid_hash_algo() {
        let key = PublicKey::from_ed25519_with_keyid_hash_algorithms(
            ED25519_1_PUBLIC_KEY,
            python_sslib_compatibility_keyid_hash_algorithms(),
        )
        .unwrap();
        assert_eq!(
            key.key_id(),
            &KeyId::from_str("a9f3ebc9b138762563a9c27b6edd439959e559709babd123e8d449ba2c18c61a")
                .unwrap(),
        );
        assert_eq!(key.typ, KeyType::Ed25519);
        assert_eq!(key.scheme, SignatureScheme::Ed25519);
    }

    #[test]
    fn rsa_2048_read_pkcs8_and_sign() {
        let msg = b"test";

        let key = PrivateKey::from_pkcs8(RSA_2048_PK8, SignatureScheme::RsaSsaPssSha256).unwrap();
        let sig = key.sign(msg).unwrap();
        key.public.verify(msg, &sig).unwrap();

        let key = PrivateKey::from_pkcs8(RSA_2048_PK8, SignatureScheme::RsaSsaPssSha512).unwrap();
        let sig = key.sign(msg).unwrap();
        key.public.verify(msg, &sig).unwrap();
    }

    #[test]
    fn rsa_4096_read_pkcs8_and_sign() {
        let msg = b"test";

        let key = PrivateKey::from_pkcs8(RSA_4096_PK8, SignatureScheme::RsaSsaPssSha256).unwrap();
        let sig = key.sign(msg).unwrap();
        key.public.verify(msg, &sig).unwrap();

        let key = PrivateKey::from_pkcs8(RSA_4096_PK8, SignatureScheme::RsaSsaPssSha512).unwrap();
        let sig = key.sign(msg).unwrap();
        key.public.verify(msg, &sig).unwrap();
    }

    #[test]
    fn extract_pkcs1_from_rsa_2048_pkcs8() {
        let res = extract_rsa_pub_from_pkcs8(RSA_2048_PK8).unwrap();
        assert_eq!(res.as_slice(), RSA_2048_PKCS1);
    }

    #[test]
    fn extract_pkcs1_from_rsa_4096_pkcs8() {
        let res = extract_rsa_pub_from_pkcs8(RSA_4096_PK8).unwrap();
        assert_eq!(res.as_slice(), RSA_4096_PKCS1);
    }

    #[test]
    fn ed25519_read_pkcs8_and_sign() {
        let key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap();
        let msg = b"test";

        let sig = key.sign(msg).unwrap();

        let pub_key =
            PublicKey::from_spki(&key.public.as_spki().unwrap(), SignatureScheme::Ed25519).unwrap();

        assert_eq!(pub_key.verify(msg, &sig), Ok(()));

        // Make sure we match what ring expects.
        let ring_key = ring::signature::Ed25519KeyPair::from_pkcs8(ED25519_1_PK8).unwrap();
        assert_eq!(key.public().as_bytes(), ring_key.public_key().as_ref());
        assert_eq!(sig.value().as_bytes(), ring_key.sign(msg).as_ref());

        // Make sure verification fails with the wrong key.
        let bad_pub_key = PrivateKey::from_pkcs8(ED25519_2_PK8, SignatureScheme::Ed25519)
            .unwrap()
            .public()
            .clone();

        assert_eq!(bad_pub_key.verify(msg, &sig), Err(Error::BadSignature));
    }

    #[test]
    fn ecdsa_read_pkcs8_and_sign() {
        let msg = b"test";

        let key = PrivateKey::from_pkcs8(ECDSA_PK8, SignatureScheme::EcdsaP256Sha256).unwrap();
        let sig = key.sign(msg).unwrap();
        key.public.verify(msg, &sig).unwrap();

        let key = PrivateKey::from_pkcs8(ECDSA_PK8, SignatureScheme::EcdsaP256Sha256).unwrap();
        let sig = key.sign(msg).unwrap();
        key.public.verify(msg, &sig).unwrap();
    }

    #[test]
    fn ed25519_read_keypair_and_sign() {
        let key = PrivateKey::from_ed25519(ED25519_1_PRIVATE_KEY).unwrap();
        let pub_key = PublicKey::from_ed25519(ED25519_1_PUBLIC_KEY).unwrap();
        assert_eq!(key.public(), &pub_key);

        let msg = b"test";
        let sig = key.sign(msg).unwrap();
        assert_eq!(pub_key.verify(msg, &sig), Ok(()));

        // Make sure we match what ring expects.
        let ring_key = ring::signature::Ed25519KeyPair::from_pkcs8(ED25519_1_PK8).unwrap();
        assert_eq!(key.public().as_bytes(), ring_key.public_key().as_ref());
        assert_eq!(sig.value().as_bytes(), ring_key.sign(msg).as_ref());

        // Make sure verification fails with the wrong key.
        let bad_pub_key = PrivateKey::from_pkcs8(ED25519_2_PK8, SignatureScheme::Ed25519)
            .unwrap()
            .public()
            .clone();

        assert_eq!(bad_pub_key.verify(msg, &sig), Err(Error::BadSignature));
    }

    #[test]
    fn ed25519_read_keypair_and_sign_with_keyid_hash_algorithms() {
        let key = PrivateKey::from_ed25519_with_keyid_hash_algorithms(
            ED25519_1_PRIVATE_KEY,
            python_sslib_compatibility_keyid_hash_algorithms(),
        )
        .unwrap();
        let pub_key = PublicKey::from_ed25519_with_keyid_hash_algorithms(
            ED25519_1_PUBLIC_KEY,
            python_sslib_compatibility_keyid_hash_algorithms(),
        )
        .unwrap();
        assert_eq!(key.public(), &pub_key);

        let msg = b"test";
        let sig = key.sign(msg).unwrap();
        assert_eq!(pub_key.verify(msg, &sig), Ok(()));

        // Make sure we match what ring expects.
        let ring_key = ring::signature::Ed25519KeyPair::from_pkcs8(ED25519_1_PK8).unwrap();
        assert_eq!(key.public().as_bytes(), ring_key.public_key().as_ref());
        assert_eq!(sig.value().as_bytes(), ring_key.sign(msg).as_ref());

        // Make sure verification fails with the wrong key.
        let bad_pub_key = PrivateKey::from_pkcs8(ED25519_2_PK8, SignatureScheme::Ed25519)
            .unwrap()
            .public()
            .clone();

        assert_eq!(bad_pub_key.verify(msg, &sig), Err(Error::BadSignature));
    }

    #[test]
    fn serde_key_id() {
        let s = "4750eaf6878740780d6f97b12dbad079fb012bec88c78de2c380add56d3f51db";
        let jsn = json!(s);
        let parsed: KeyId = serde_json::from_str(&format!("\"{}\"", s)).unwrap();
        assert_eq!(parsed, KeyId::from_str(s).unwrap());
        let encoded = serde_json::to_value(&parsed).unwrap();
        assert_eq!(encoded, jsn);
    }

    #[test]
    fn serde_signature_value() {
        let s = "4750eaf6878740780d6f97b12dbad079fb012bec88c78de2c380add56d3f51db";
        let jsn = json!(s);
        let parsed: SignatureValue = serde_json::from_str(&format!("\"{}\"", s)).unwrap();
        assert_eq!(parsed, SignatureValue::from_hex(s).unwrap());
        let encoded = serde_json::to_value(&parsed).unwrap();
        assert_eq!(encoded, jsn);
    }

    #[test]
    fn serde_rsa_public_key() {
        let der = RSA_2048_SPKI;
        let pub_key = PublicKey::from_spki(der, SignatureScheme::RsaSsaPssSha256).unwrap();
        let pem = pem::encode(&pem::Pem::new(PEM_PUBLIC_KEY.to_string(), der.to_vec()))
            .trim()
            .replace("\r\n", "\n")
            .to_string();
        let encoded = serde_json::to_value(&pub_key).unwrap();
        let jsn = json!({
            "keyid": "c2620e94b6ff57f433c24436013a89d403fa6934a2ee490f44f897176c2c52e9",
            "keytype": "rsa",
            "scheme": "rsassa-pss-sha256",
            "keyid_hash_algorithms": ["sha256", "sha512"],
            "keyval": {
                "private": "",
                "public": pem,
            }
        });
        assert_eq!(encoded, jsn);
        let decoded: PublicKey = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, pub_key);
    }

    #[test]
    fn de_ser_rsa_public_key_with_keyid_hash_algo() {
        let pem = pem::encode(&pem::Pem::new(
            PEM_PUBLIC_KEY.to_string(),
            RSA_2048_SPKI.to_vec(),
        ))
        .trim()
        .replace("\r\n", "\n")
        .to_string();

        let original = json!({
            "keyid": "c2620e94b6ff57f433c24436013a89d403fa6934a2ee490f44f897176c2c52e9",
            "keytype": "rsa",
            "scheme": "rsassa-pss-sha256",
            "keyid_hash_algorithms": ["sha256", "sha512"],
            "keyval": {
                "private": "",
                "public": pem,
            }
        });

        let decoded: PublicKey = serde_json::from_value(original.clone()).unwrap();
        let encoded = serde_json::to_value(&decoded).unwrap();

        assert_eq!(original, encoded);
    }

    #[test]
    fn de_ser_rsa_public_key_without_keyid_hash_algo() {
        let pem = pem::encode(&pem::Pem::new(
            PEM_PUBLIC_KEY.to_string(),
            RSA_2048_SPKI.to_vec(),
        ))
        .trim()
        .replace("\r\n", "\n")
        .to_string();

        let original = json!({
            "keyid": "3733b56bfa06e9d731b561891d413569e0795c74d9c3434bc6373ff809683dde",
            "keytype": "rsa",
            "scheme": "rsassa-pss-sha256",
            "keyval": {
                "private": "",
                "public": pem,
            }
        });

        let decoded: PublicKey = serde_json::from_value(original.clone()).unwrap();
        let encoded = serde_json::to_value(&decoded).unwrap();

        assert_eq!(original, encoded);
    }

    #[test]
    fn serde_ed25519_public_key() {
        let pub_key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519)
            .unwrap()
            .public()
            .clone();

        let pub_key = PublicKey::from_ed25519_with_keyid_hash_algorithms(
            pub_key.as_bytes().to_vec(),
            python_sslib_compatibility_keyid_hash_algorithms(),
        )
        .unwrap();
        let encoded = serde_json::to_value(&pub_key).unwrap();
        let jsn = json!({
            "keyid": "a9f3ebc9b138762563a9c27b6edd439959e559709babd123e8d449ba2c18c61a",
            "keytype": "ed25519",
            "scheme": "ed25519",
            "keyid_hash_algorithms": ["sha256", "sha512"],
            "keyval": {
                "private": "",
                "public": HEXLOWER.encode(pub_key.as_bytes()),
            }
        });
        assert_eq!(encoded, jsn);
        let decoded: PublicKey = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, pub_key);
    }

    #[test]
    fn de_ser_ed25519_public_key_with_keyid_hash_algo() {
        let pub_key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519)
            .unwrap()
            .public()
            .clone();
        let pub_key = PublicKey::from_ed25519_with_keyid_hash_algorithms(
            pub_key.as_bytes().to_vec(),
            python_sslib_compatibility_keyid_hash_algorithms(),
        )
        .unwrap();
        let original = json!({
            "keyid": "a9f3ebc9b138762563a9c27b6edd439959e559709babd123e8d449ba2c18c61a",
            "keytype": "ed25519",
            "scheme": "ed25519",
            "keyid_hash_algorithms": ["sha256", "sha512"],
            "keyval": {
                "private": "",
                "public": HEXLOWER.encode(pub_key.as_bytes()),
            }
        });

        let encoded: PublicKey = serde_json::from_value(original.clone()).unwrap();
        let decoded = serde_json::to_value(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn de_ser_ed25519_public_key_without_keyid_hash_algo() {
        let pub_key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519)
            .unwrap()
            .public()
            .clone();
        let pub_key =
            PublicKey::from_ed25519_with_keyid_hash_algorithms(pub_key.as_bytes().to_vec(), None)
                .unwrap();
        let original = json!({
            "keyid": "e0294a3f17cc8563c3ed5fceb3bd8d3f6bfeeaca499b5c9572729ae015566554",
            "keytype": "ed25519",
            "scheme": "ed25519",
            "keyval": {
                "private": "",
                "public": HEXLOWER.encode(pub_key.as_bytes()),
            }
        });

        let encoded: PublicKey = serde_json::from_value(original.clone()).unwrap();
        let decoded = serde_json::to_value(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn serde_ecdsa_public_key() {
        let pub_key = PrivateKey::from_pkcs8(ECDSA_PK8, SignatureScheme::EcdsaP256Sha256)
            .unwrap()
            .public()
            .clone();
        let pub_key = PublicKey::from_ecdsa_with_keyid_hash_algorithms(
            pub_key.as_bytes().to_vec(),
            python_sslib_compatibility_keyid_hash_algorithms(),
        )
        .unwrap();
        let encoded = serde_json::to_value(&pub_key).unwrap();
        let jsn = json!({
            "keyid": "562b12b3f14a84bfe37d9de25c64f2e98eea7ab1918366361a7e37b5ab83b5f3",
            "keytype": "ecdsa",
            "scheme": "ecdsa-sha2-nistp256",
            "keyid_hash_algorithms": ["sha256", "sha512"],
            "keyval": {
                "public": HEXLOWER.encode(pub_key.as_bytes()),
                "private": ""
            }
        });
        assert_eq!(encoded, jsn);
        let decoded: PublicKey = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, pub_key);
    }

    #[test]
    fn serde_signature() {
        let key = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap();
        let msg = b"test";
        let sig = key.sign(msg).unwrap();
        let encoded = serde_json::to_value(&sig).unwrap();
        let jsn = json!({
            "keyid": "a9f3ebc9b138762563a9c27b6edd439959e559709babd123e8d449ba2c18c61a",
            "sig": "fe4d13b2a73c033a1de7f5107b205fc7ba0e1566cb95b92349cae6aa453\
                8956013bfe0f7bf977cb072bb65e8782b5f33a0573fe78816299a017ca5ba55\
                9e390c",
        });
        assert_eq!(encoded, jsn);

        let decoded: Signature = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, sig);
    }

    #[test]
    fn serde_signature_without_keyid_hash_algo() {
        let key =
            PrivateKey::ed25519_from_pkcs8_with_keyid_hash_algorithms(ED25519_1_PK8, None).unwrap();
        let msg = b"test";
        let sig = key.sign(msg).unwrap();
        let encoded = serde_json::to_value(&sig).unwrap();
        let jsn = json!({
            "keyid": "e0294a3f17cc8563c3ed5fceb3bd8d3f6bfeeaca499b5c9572729ae015566554",
            "sig": "fe4d13b2a73c033a1de7f5107b205fc7ba0e1566cb95b92349cae6aa453\
                    8956013bfe0f7bf977cb072bb65e8782b5f33a0573fe78816299a017ca5ba55\
                    9e390c",
        });
        assert_eq!(encoded, jsn);

        let decoded: Signature = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, sig);
    }

    #[test]
    #[cfg(not(any(target_os = "fuchsia", windows)))]
    fn new_rsa_key() {
        let bytes = PrivateKey::new(KeyType::Rsa).unwrap();
        let _ = PrivateKey::from_pkcs8(&bytes, SignatureScheme::RsaSsaPssSha256).unwrap();
    }

    #[test]
    fn new_ed25519_key() {
        let bytes = PrivateKey::new(KeyType::Ed25519).unwrap();
        let _ = PrivateKey::from_pkcs8(&bytes, SignatureScheme::Ed25519).unwrap();
    }

    #[test]
    fn new_ecdsa_key() {
        let bytes = PrivateKey::new(KeyType::Ecdsa).unwrap();
        let _ = PrivateKey::from_pkcs8(&bytes, SignatureScheme::EcdsaP256Sha256).unwrap();
    }

    #[test]
    fn test_public_key_eq() {
        let key256 = PublicKey::from_spki(RSA_2048_SPKI, SignatureScheme::RsaSsaPssSha256).unwrap();
        let key512 = PublicKey::from_spki(RSA_2048_SPKI, SignatureScheme::RsaSsaPssSha512).unwrap();
        assert_eq!(key256, key256);
        assert_ne!(key256, key512);
    }

    #[test]
    fn test_public_key_hash() {
        use std::hash::{BuildHasher, Hash, Hasher};

        let key256 = PublicKey::from_spki(RSA_2048_SPKI, SignatureScheme::RsaSsaPssSha256).unwrap();
        let key512 = PublicKey::from_spki(RSA_2048_SPKI, SignatureScheme::RsaSsaPssSha512).unwrap();

        let state = std::collections::hash_map::RandomState::new();
        let mut hasher256 = state.build_hasher();
        key256.hash(&mut hasher256);

        let mut hasher512 = state.build_hasher();
        key512.hash(&mut hasher512);

        assert_ne!(hasher256.finish(), hasher512.finish());
    }

    #[test]
    fn parse_public_rsa_from_pem_spki() {
        let pem = str::from_utf8(&DEMO_PUBLIC_KEY).unwrap();
        let key = PublicKey::from_pem_spki(&pem, SignatureScheme::RsaSsaPssSha256).unwrap();
        assert_eq!(key.typ, KeyType::Rsa);
        assert_eq!(key.scheme, SignatureScheme::RsaSsaPssSha256);
    }

    #[test]
    fn parse_public_ed25519_from_pem_spki() {
        let pem = pubkey_as_pem(&PublicKey::from_ed25519(ED25519_1_PUBLIC_KEY).unwrap());
        let key = PublicKey::from_pem_spki(&pem, SignatureScheme::Ed25519).unwrap();
        assert_eq!(key.typ, KeyType::Ed25519);
        assert_eq!(key.scheme, SignatureScheme::Ed25519);
    }

    #[test]
    fn parse_public_key_ecdsa_from_pem_spki() {
        let pem = str::from_utf8(&ECDSA_PUBLIC_KEY).unwrap();
        let public_key = PublicKey::from_pem_spki(&pem, SignatureScheme::EcdsaP256Sha256).unwrap();
        assert_eq!(public_key.typ(), &KeyType::Ecdsa);
        assert_eq!(public_key.scheme(), &SignatureScheme::EcdsaP256Sha256);
    }

    #[test]
    fn compatibility_keyid_with_python_in_toto() {
        let der = pem::parse(DEMO_PUBLIC_KEY).expect("parse alice.pub in pem format failed");
        let key = PublicKey::from_spki(der.contents(), SignatureScheme::RsaSsaPssSha256)
            .expect("create PublicKey failed");
        assert_eq!(key.key_id.0, DEMO_KEY_ID);
    }

    #[test]
    fn compatibility_rsa_verify_with_python_in_toto() {
        let der = pem::parse(DEMO_PUBLIC_KEY).expect("parse alice.pub in pem format failed");
        let key = PublicKey::from_spki(der.contents(), SignatureScheme::RsaSsaPssSha256)
            .expect("create PublicKey failed");
        let meta: Metablock = serde_json::from_slice(DEMO_LAYOUT).expect("failed to deserialize");
        let msg = meta.metadata.to_bytes().expect("failed to canonicalize");
        let msg = String::from_utf8(msg)
            .expect("failed to parse metadata string")
            .replace("\\n", "\n");
        let sig = &meta.signatures[0];
        let res = key.verify(msg.as_bytes(), &sig);
        assert!(res.is_ok(), "{:?}", res);
    }

    fn pubkey_as_pem(key: &PublicKey) -> String {
        pem::encode(&pem::Pem::new(
            PEM_PUBLIC_KEY.to_string(),
            key.as_spki().unwrap(),
        ))
        .trim()
        .replace("\r\n", "\n")
        .to_string()
    }
}
