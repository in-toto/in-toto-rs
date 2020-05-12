//! This crate provides an API for talking to repositories that implements in-toto
//! # Interoperability
//!
//! It should be noted that historically the TUF spec defined exactly one metadata format and one
//! way of organizing metadata within a repository. Thus, all TUF implementation could perfectly
//! interoperate. The TUF spec has moved to describing *how a framework should behave* leaving many
//! of the detais up to the implementor. Therefore, there are **zero** guarantees that this library
//! will work with any other TUF implementation. Should you want to access a TUF repository that
//! uses `rust-tuf` as its backend from another language, ASN.1 modules and metadata schemas are
//! provided that will allow you to interoperate with this library.
//!
//! # Implementation Considerations
//!
//! ## Key Management
//!
//! Part of TUF is that it acts as its own PKI, and there is no integration that needs to be done
//! for managing keys.
//!
//! Note: No two private keys that are generated should ever exist on the same hardware. When a
//! step says "generate `N` keys," the implication is that these `N` keys are generated on `N`
//! devices.
//!
//! The first set of keys that need to be generated at the root keys that are used to sign the root
//! metadata. The root should be defined with the following properties:
//!
//! - Minimum:
//!   - 3 keys
//!   - threshold of 2
//! - Recommended:
//!   - 5 keys
//!   - threshold of 3
//!
//! If a threshold of root keys are compromised, then the entire system is compromised and TUF
//! clients will need to be manually updated. Similarly, if some `X` keys are lost such that the
//! threshold `N` cannot be reached, then clients will also need to be manually updated. Both of
//! situations are considered critically unsafe. Whatever number of keys are used, it should be
//! assumed that some small number may be lost or compromised.
//!
//! These root keys **MUST** be kept offline on secure media.


//#![deny(missing_docs)]
#![allow(
    clippy::collapsible_if,
    clippy::implicit_hasher,
    clippy::new_ret_no_self,
    clippy::op_ref,
    clippy::too_many_arguments
)]

pub mod runlib;
pub mod crypto;
pub mod error;
pub mod interchange;
pub mod metadata;
pub mod verification;
//pub mod in_toto;

mod format_hex;

pub use crate::error::*;
//pub use crate::in_toto::*;

/// Alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;
