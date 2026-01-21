//! # zero-auth-integrations
//!
//! Integrations & Events subsystem for zero-auth.
//!
//! ## Responsibilities
//!
//! - Integration service registration and authentication
//! - mTLS certificate validation
//! - Server-Sent Events (SSE) streaming
//! - Webhook delivery with retry logic
//! - Event filtering by namespace
//! - Revocation event publishing

pub mod errors;
mod service;
pub mod traits;
pub mod types;
pub mod webhook;

pub use errors::{Error, Result};
pub use service::{has_event_scope, should_deliver_event, IntegrationsService};
pub use traits::Integrations;
pub use types::*;
