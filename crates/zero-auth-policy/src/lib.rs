//! # zero-auth-policy
//!
//! Policy Engine for authorization, rate limiting, and approval requirements.

#![warn(clippy::all)]

pub mod types;
pub mod errors;
pub mod engine;
pub mod evaluator;
pub mod rate_limit;

pub use types::*;
pub use errors::{PolicyError, Result};
pub use engine::{PolicyEngine, PolicyEngineImpl};
pub use evaluator::PolicyEvaluator;
pub use rate_limit::RateLimiter;
