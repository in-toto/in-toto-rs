//! Error types and converters.

use data_encoding::DecodeError;
use std::io;
use std::path::Path;
use std::str;
use thiserror::Error;

/// Error type for all in-toto related errors.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    /// The metadata had a bad signature.
    #[error("bad signature")]
    BadSignature,

    /// There was a problem encoding or decoding.
    #[error("encoding: {0}")]
    Encoding(String),

    /// An illegal argument was passed into a function.
    #[error("illegal argument: {0}")]
    IllegalArgument(String),

    /// There were no available hash algorithms.
    #[error("no supported hash algorithm")]
    NoSupportedHashAlgorithm,

    /// The metadata or target was not found.
    #[error("not found")]
    NotFound,

    /// Opaque error type, to be interpreted similar to HTTP 500. Something went wrong, and you may
    /// or may not be able to do anything about it.
    #[error("opaque: {0}")]
    Opaque(String),

    /// There was a library internal error. These errors are *ALWAYS* bugs and should be reported.
    #[error("programming: {0}")]
    Programming(String),

    /// The target is unavailable. This may mean it is either not in the metadata or the metadata
    /// chain to the target cannot be fully verified.
    #[error("target unavailable")]
    TargetUnavailable,

    /// There is no known or available hash algorithm.
    #[error("unknown hash algorithm: {0}")]
    UnknownHashAlgorithm(String),

    /// There is no known or available key type.
    #[error("unknown key type: {0}")]
    UnknownKeyType(String),

    /// The metadata or target failed to verify.
    #[error("verification failure: {0}")]
    VerificationFailure(String),

    #[error("prefix selection failure: {0}")]
    LinkGatheringError(String),

    #[error("do Pre-Authentication Encoding failed: {0}")]
    PAEParseFailed(String),

    #[error("runlib failed: {0}")]
    RunLibError(String),

    #[error("attestation state and predicate version dismatch: {0} and {1}")]
    AttestationFormatDismatch(String, String),

    #[error("convertion from string failed: {0}")]
    StringConvertFailed(String),

    #[error("artifact rule error: {0}")]
    ArtifactRuleError(String),
}

impl From<serde_json::error::Error> for Error {
    fn from(err: serde_json::error::Error) -> Error {
        Error::Encoding(format!("JSON: {:?}", err))
    }
}

impl Error {
    /// Helper to include the path that causd the error for FS I/O errors.
    pub fn from_io(err: &io::Error, path: &Path) -> Error {
        Error::Opaque(format!("Path {:?} : {:?}", path, err))
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        match err.kind() {
            std::io::ErrorKind::NotFound => Error::NotFound,
            _ => Error::Opaque(format!("IO: {:?}", err)),
        }
    }
}

impl From<DecodeError> for Error {
    fn from(err: DecodeError) -> Error {
        Error::Encoding(format!("{:?}", err))
    }
}

impl From<derp::Error> for Error {
    fn from(err: derp::Error) -> Error {
        Error::Encoding(format!("DER: {:?}", err))
    }
}

impl From<str::Utf8Error> for Error {
    fn from(err: str::Utf8Error) -> Error {
        Error::Opaque(format!("Parse utf8: {:?}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_io_error_display_string() {
        let err = Error::from(io::Error::from(std::io::ErrorKind::NotFound));
        assert_eq!(err.to_string(), "not found");
        assert_eq!(Error::NotFound.to_string(), "not found");

        let err =
            Error::from(io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert_eq!(err.to_string(), "opaque: IO: Kind(PermissionDenied)");
    }
}
