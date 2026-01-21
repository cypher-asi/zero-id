use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("Session not found: {0}")]
    SessionNotFound(Uuid),

    #[error("Session expired: session_id={session_id}, expired_at={expired_at}")]
    SessionExpired { session_id: Uuid, expired_at: u64 },

    #[error("Session revoked: {reason}")]
    SessionRevoked { reason: String },

    #[error("Identity frozen")]
    IdentityFrozen,

    #[error("Machine revoked")]
    MachineRevoked,

    #[error("Token expired")]
    TokenExpired,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Invalid algorithm: found {found:?}, expected EdDSA")]
    InvalidAlgorithm { found: String },

    #[error("Missing key ID in JWT header")]
    MissingKeyId,

    #[error("Unknown key ID: {0}")]
    UnknownKeyId(String),

    #[error("Key retired: {kid} at {retired_at:?}")]
    KeyRetired {
        kid: String,
        retired_at: Option<u64>,
    },

    #[error("Refresh token expired")]
    RefreshTokenExpired,

    #[error("Refresh token reuse detected: family={token_family_id}, generation={generation}")]
    RefreshTokenReuse {
        token_family_id: Uuid,
        generation: u32,
    },

    #[error("Refresh token not found")]
    RefreshTokenNotFound,

    #[error("Session binding mismatch")]
    SessionBindingMismatch,

    #[error("Machine binding mismatch")]
    MachineBindingMismatch,

    #[error("Token family revoked")]
    TokenFamilyRevoked,

    #[error("Token generation failed: retry_allowed={retry_allowed}, error={original_error}")]
    TokenGenerationFailed {
        retry_allowed: bool,
        retry_until: u64,
        original_error: String,
    },

    #[error("Invalid audience")]
    InvalidAudience,

    #[error("Identity not active")]
    IdentityNotActive,

    #[error("Stale revocation epoch: token_epoch={token_epoch}, machine_epoch={machine_epoch}, message={message}")]
    StaleRevocationEpoch {
        token_epoch: u64,
        machine_epoch: u64,
        message: String,
    },

    #[error("JWT encoding error: {0}")]
    JwtEncodingError(#[from] jsonwebtoken::errors::Error),

    #[error("Storage error: {0}")]
    StorageError(#[from] zero_auth_storage::StorageError),

    #[error("Identity core error: {0}")]
    IdentityCoreError(#[from] zero_auth_identity_core::IdentityCoreError),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] zero_auth_crypto::CryptoError),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Other error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, SessionError>;
