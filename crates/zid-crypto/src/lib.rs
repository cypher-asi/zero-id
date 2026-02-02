//! # zid-crypto
//!
//! Cryptographic primitives for zid system.
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

// Re-export KeyScheme for easy access
pub use keys::KeyScheme;

// Re-export PQ key types (always available)
pub use keys::{MlDsaKeyPair, MlKemKeyPair};

// Re-export PQ derivation functions (always available)
pub use derivation::{
    derive_machine_keypair_with_scheme, derive_machine_pq_kem_seed, derive_machine_pq_signing_seed,
};

// Re-export managed identity derivation
pub use derivation::derive_managed_identity_signing_keypair;
