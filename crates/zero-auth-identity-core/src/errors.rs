//! Identity Core error types.

use thiserror::Error;
use uuid::Uuid;

/// Identity Core errors
#[derive(Debug, Error)]
pub enum IdentityCoreError {
    /// Identity not found
    #[error("Identity not found: {0}")]
    NotFound(Uuid),

    /// Identity not active
    #[error("Identity not active: status={status:?}, reason={reason}")]
    IdentityNotActive {
        status: crate::types::IdentityStatus,
        reason: String,
    },

    /// Invalid authorization signature
    #[error("Invalid authorization signature")]
    InvalidAuthorizationSignature,

    /// Machine already exists
    #[error("Machine already exists: {0}")]
    MachineAlreadyExists(Uuid),

    /// Machine not found
    #[error("Machine not found: {0}")]
    MachineNotFound(Uuid),

    /// Insufficient approvals
    #[error("Insufficient approvals: required={required}, provided={provided}")]
    InsufficientApprovals { required: usize, provided: usize },

    /// Approval expired
    #[error("Approval expired")]
    ApprovalExpired,

    /// Invalid approval signature
    #[error("Invalid approval signature")]
    InvalidApprovalSignature,

    /// Invalid approving machine
    #[error("Invalid approving machine")]
    InvalidApprovingMachine,

    /// Duplicate approval
    #[error("Duplicate approval from machine: {0}")]
    DuplicateApproval(Uuid),

    /// Policy denied
    #[error("Policy denied: {0}")]
    PolicyDenied(String),

    /// MFA required
    #[error("MFA required: {0:?}")]
    MfaRequired(Vec<zero_auth_policy::AuthFactor>),

    /// Not a namespace member
    #[error("Identity {identity_id} is not a member of namespace {namespace_id}")]
    NotNamespaceMember {
        identity_id: Uuid,
        namespace_id: Uuid,
    },

    /// Insufficient machines for unfreeze
    #[error("Insufficient machines for unfreeze: available={available}, message={message}")]
    InsufficientMachinesForUnfreeze { available: usize, message: String },

    /// No machines for unfreeze
    #[error("No machines for unfreeze: {message}")]
    NoMachinesForUnfreeze { message: String },

    /// Identity frozen
    #[error("Identity frozen: {0}")]
    IdentityFrozen(Uuid),

    /// Not frozen
    #[error("Identity not frozen: {0}")]
    NotFrozen(Uuid),

    /// Already revoked
    #[error("Machine already revoked: {0}")]
    AlreadyRevoked(Uuid),

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(#[from] zero_auth_storage::StorageError),

    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] zero_auth_crypto::CryptoError),

    /// Policy error
    #[error("Policy error: {0}")]
    Policy(#[from] zero_auth_policy::PolicyError),

    /// Other error
    #[error("Other error: {0}")]
    Other(String),
}

/// Result type for Identity Core operations
pub type Result<T> = std::result::Result<T, IdentityCoreError>;
