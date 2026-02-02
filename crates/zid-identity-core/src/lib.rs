//! # zid-identity-core
//!
//! Identity Core subsystem for cryptographic identity management.
//!
//! This is the foundational subsystem responsible for:
//! - Identity creation and lifecycle management
//! - Machine Key registry and enrollment
//! - Neural Key ceremonies (recovery, rotation)
//! - Namespace management

#![warn(clippy::all)]

pub mod errors;
mod service;
pub mod traits;
pub mod types;

pub use errors::{IdentityCoreError, Result};
pub use service::{
    CreateManagedIdentityRequest, CreateManagedIdentityResponse, IdentityCoreService,
    TierStatusResponse, UpgradeIdentityRequest, UpgradeIdentityResponse,
};
pub use traits::{
    CreateManagedIdentityParams, CreateManagedIdentityResult, EventPublisher, IdentityCore,
};
pub use types::*;
