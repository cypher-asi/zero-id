//! Auth Methods subsystem for zero-auth
//!
//! This crate provides multiple authentication mechanisms:
//! - Machine Key challenge-response (cryptographic)
//! - Email + password (traditional)
//! - OAuth providers (Google, X, Epic Games)
//! - EVM wallet signatures (blockchain-based)
//! - Multi-factor authentication (TOTP)
//!
//! All authentication methods enforce MFA when enabled and integrate
//! with the Policy Engine for authorization decisions.

#![warn(missing_docs)]

pub mod challenge;
pub mod errors;
pub mod mfa;
pub mod oauth;
pub mod service;
pub mod traits;
pub mod types;
pub mod wallet;

// Re-exports
pub use errors::{AuthMethodsError, Result};
pub use service::AuthMethodsService;
pub use traits::AuthMethods;
pub use types::*;
