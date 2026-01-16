//! Error types for integrations subsystem.

use thiserror::Error;

/// Result type alias for integrations operations
pub type Result<T> = std::result::Result<T, Error>;

/// Integrations subsystem errors
#[derive(Debug, Error)]
pub enum Error {
    /// Storage operation failed
    #[error("Storage error: {0}")]
    Storage(#[from] zero_auth_storage::StorageError),

    /// Unknown integration service
    #[error("Unknown integration service")]
    UnknownService,

    /// Service has been revoked
    #[error("Service has been revoked")]
    ServiceRevoked,

    /// Client certificate expired
    #[error("Client certificate expired")]
    CertificateExpired,

    /// Invalid certificate fingerprint
    #[error("Invalid certificate fingerprint")]
    InvalidCertificateFingerprint,

    /// Certificate validation failed
    #[error("Certificate validation failed: {0}")]
    CertificateValidationFailed(String),

    /// Service already registered
    #[error("Service already registered with this certificate")]
    ServiceAlreadyRegistered,

    /// No webhook configured
    #[error("No webhook configured for service")]
    NoWebhookConfigured,

    /// Webhook delivery failed
    #[error("Webhook delivery failed: {0}")]
    WebhookDeliveryFailed(String),

    /// Invalid webhook signature
    #[error("Invalid webhook signature")]
    InvalidWebhookSignature,

    /// Webhook too old (replay protection)
    #[error("Webhook timestamp too old")]
    WebhookTooOld,

    /// Event already processed (deduplication)
    #[error("Event already processed")]
    EventAlreadyProcessed,

    /// Invalid namespace filter
    #[error("Invalid namespace filter")]
    InvalidNamespaceFilter,

    /// Invalid scope configuration
    #[error("Invalid scope configuration")]
    InvalidScope,

    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Bincode error
    #[error("Bincode error: {0}")]
    Bincode(#[from] bincode::Error),

    /// Invalid event sequence
    #[error("Invalid event sequence")]
    InvalidEventSequence,

    /// Sequence generation failed
    #[error("Sequence generation failed")]
    SequenceGenerationFailed,

    /// Service name too long
    #[error("Service name must be <= 128 characters")]
    ServiceNameTooLong,

    /// Webhook URL invalid
    #[error("Webhook URL invalid: {0}")]
    InvalidWebhookUrl(String),

    /// Too many namespaces in filter
    #[error("Too many namespaces in filter (max 100)")]
    TooManyNamespaces,

    /// Generic error
    #[error("{0}")]
    Other(String),
}
