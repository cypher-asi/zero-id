//! Cryptographic error types.

use thiserror::Error;

/// Cryptographic operation errors
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Invalid key size
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize {
        /// Expected key size in bytes
        expected: usize,
        /// Actual key size in bytes
        actual: usize,
    },

    /// Invalid nonce size
    #[error("Invalid nonce size: expected {expected}, got {actual}")]
    InvalidNonceSize {
        /// Expected nonce size in bytes
        expected: usize,
        /// Actual nonce size in bytes
        actual: usize,
    },

    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// Signature verification failed
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Invalid input data
    #[error("Invalid input data: {0}")]
    InvalidInput(String),

    /// Random number generation failed
    #[error("Random number generation failed: {0}")]
    RandomGenerationFailed(String),

    /// Argon2 hashing failed
    #[error("Argon2 hashing failed: {0}")]
    Argon2Failed(String),

    /// Invalid hash format
    #[error("Invalid hash format")]
    InvalidHashFormat,

    /// Ed25519 error
    #[error("Ed25519 error: {0}")]
    Ed25519Error(String),

    /// X25519 error
    #[error("X25519 error: {0}")]
    X25519Error(String),

    /// HKDF error
    #[error("HKDF error: insufficient output length")]
    HkdfError,

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// Shamir split operation failed
    #[error("Shamir split failed: {0}")]
    ShamirSplitFailed(String),

    /// Shamir combine operation failed
    #[error("Shamir combine failed: {0}")]
    ShamirCombineFailed(String),

    /// Insufficient shards for reconstruction
    #[error("Insufficient Neural Shards: need {required}, got {provided}")]
    InsufficientShards {
        /// Minimum required shards
        required: usize,
        /// Number of shards provided
        provided: usize,
    },

    /// Too many shards provided
    #[error("Too many Neural Shards: maximum {maximum}, got {provided}")]
    TooManyShards {
        /// Maximum allowed shards
        maximum: usize,
        /// Number of shards provided
        provided: usize,
    },

    /// Duplicate shard index
    #[error("Duplicate Neural Shard index: {0}")]
    DuplicateShardIndex(u8),

    /// Invalid shard format
    #[error("Invalid Neural Shard format: {0}")]
    InvalidShardFormat(String),
}

/// Result type for cryptographic operations
pub type Result<T> = std::result::Result<T, CryptoError>;
