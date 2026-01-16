//! Policy engine error types.

use thiserror::Error;

/// Policy engine errors
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Policy evaluation denied
    #[error("Policy denied: {0}")]
    PolicyDenied(String),

    /// Identity frozen
    #[error("Identity frozen: {0}")]
    IdentityFrozen(String),

    /// Machine revoked
    #[error("Machine revoked")]
    MachineRevoked,

    /// Rate limit exceeded
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    /// MFA required
    #[error("MFA required")]
    MfaRequired,

    /// Insufficient capabilities
    #[error("Insufficient capabilities: missing {0:?}")]
    InsufficientCapabilities(Vec<String>),

    /// Approval required
    #[error("Approval required: {required} approvals needed, {provided} provided")]
    ApprovalRequired { required: u8, provided: u8 },

    /// Internal error
    #[error("Internal policy error: {0}")]
    Internal(String),
}

/// Result type for policy operations
pub type Result<T> = std::result::Result<T, PolicyError>;
