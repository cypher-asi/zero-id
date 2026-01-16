//! # zero-auth-identity-core
//!
//! Identity Core subsystem for cryptographic identity management.
//!
//! This is the foundational subsystem responsible for:
//! - Identity creation and lifecycle management
//! - Machine Key registry and enrollment
//! - Neural Key ceremonies (recovery, rotation)
//! - Namespace management

#![warn(clippy::all)]

pub mod types;
pub mod errors;
pub mod traits;
pub mod service;

pub use types::*;
pub use errors::{IdentityCoreError, Result};
pub use traits::{IdentityCore, EventPublisher};
pub use service::IdentityCoreService;
