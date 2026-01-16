//! # zero-auth-crypto
//!
//! Cryptographic primitives for zero-auth system.
//!
//! This crate provides all cryptographic operations according to the specification in
//! `docs/requirements/cryptographic-constants.md`.
//!
//! ## Security Properties
//!
//! - All sensitive material is zeroized after use
//! - Constant-time operations where applicable
//! - No unsafe code
//! - Strict domain separation for all key derivations

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod constants;
pub mod errors;
pub mod hashing;
pub mod keys;
pub mod signatures;
pub mod encryption;
pub mod derivation;

pub use constants::*;
pub use errors::CryptoError;
pub use hashing::*;
pub use keys::*;
pub use signatures::*;
pub use encryption::*;
pub use derivation::*;
