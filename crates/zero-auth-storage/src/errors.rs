//! Storage error types.

use thiserror::Error;

/// Storage operation errors
#[derive(Debug, Error)]
pub enum StorageError {
    /// Database error
    #[error("Database error: {0}")]
    Database(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// Not found
    #[error("Key not found")]
    NotFound,

    /// Already exists
    #[error("Key already exists")]
    AlreadyExists,

    /// Invalid column family
    #[error("Invalid column family: {0}")]
    InvalidColumnFamily(String),

    /// Transaction error
    #[error("Transaction error: {0}")]
    TransactionError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Result type for storage operations
pub type Result<T> = std::result::Result<T, StorageError>;
