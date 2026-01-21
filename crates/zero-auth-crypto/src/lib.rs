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
pub mod derivation;
pub mod encryption;
pub mod errors;
pub mod hashing;
pub mod keys;
pub mod shamir;
pub mod signatures;
pub mod utils;

pub use constants::*;
pub use derivation::*;
pub use encryption::*;
pub use errors::CryptoError;
pub use hashing::*;
pub use keys::*;
pub use shamir::*;
pub use signatures::*;
pub use utils::*;

// Re-export Challenge types for client use
pub use signatures::{canonicalize_challenge, Challenge, EntityType};
