//! Auth Methods error types.

use thiserror::Error;
use uuid::Uuid;

/// Auth Methods errors
#[derive(Debug, Error)]
pub enum AuthMethodsError {
    /// Challenge not found or expired
    #[error("Challenge not found or expired: {0}")]
    ChallengeNotFound(Uuid),

    /// Challenge already used (replay attack detected)
    #[error("Challenge already used: {0}")]
    ChallengeAlreadyUsed(Uuid),

    /// Challenge expired
    #[error("Challenge expired")]
    ChallengeExpired,

    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// Machine revoked
    #[error("Machine revoked: {0}")]
    MachineRevoked(Uuid),

    /// Machine not found
    #[error("Machine not found: {0}")]
    MachineNotFound(Uuid),

    /// Machine not owned by identity
    #[error("Machine {machine_id} not owned by identity {identity_id}")]
    MachineNotOwned {
        /// Machine ID that was checked
        machine_id: Uuid,
        /// Identity ID that should own the machine
        identity_id: Uuid,
    },

    /// Identity frozen
    #[error("Identity frozen: {identity_id}, reason: {reason:?}")]
    IdentityFrozen {
        /// Identity ID that is frozen
        identity_id: Uuid,
        /// Reason for the freeze
        reason: Option<String>,
    },

    /// Invalid credentials (email/password)
    #[error("Invalid credentials")]
    InvalidCredentials,

    /// Email credential not found
    #[error("Email credential not found: {0}")]
    EmailCredentialNotFound(String),

    /// MFA required
    #[error("MFA verification required")]
    MfaRequired,

    /// Invalid MFA code
    #[error("Invalid MFA code")]
    InvalidMfaCode,

    /// MFA not enabled
    #[error("MFA not enabled for identity: {0}")]
    MfaNotEnabled(Uuid),

    /// MFA already enabled
    #[error("MFA already enabled for identity: {0}")]
    MfaAlreadyEnabled(Uuid),

    /// Machine ID required
    #[error("Machine ID required: {hint}")]
    MachineIdRequired {
        /// Hint for resolving the issue
        hint: String
    },

    /// Policy denied
    #[error("Policy denied: {0}")]
    PolicyDenied(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// Identity Core error
    #[error("Identity Core error: {0}")]
    IdentityCore(#[from] zero_auth_identity_core::IdentityCoreError),

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(#[from] zero_auth_storage::StorageError),

    /// Crypto error
    #[error("Crypto error: {0}")]
    Crypto(#[from] zero_auth_crypto::CryptoError),

    /// Policy error
    #[error("Policy error: {0}")]
    Policy(#[from] zero_auth_policy::PolicyError),

    /// Password hashing error
    #[error("Password hashing error: {0}")]
    PasswordHash(String),

    /// TOTP error
    #[error("TOTP error: {0}")]
    TotpError(String),

    /// OAuth configuration invalid
    #[error("OAuth configuration invalid: {0}")]
    OAuthConfigInvalid(String),

    /// OAuth provider error
    #[error("OAuth provider error: {0}")]
    OAuthProviderError(String),

    /// OAuth state not found or expired
    #[error("OAuth state not found or expired")]
    OAuthStateNotFound,

    /// OAuth state invalid (not found, expired, or already used)
    #[error("OAuth state invalid")]
    OAuthStateInvalid,

    /// OAuth state already used
    #[error("OAuth state already used")]
    OAuthStateAlreadyUsed,

    /// OAuth not linked
    #[error("OAuth account not linked to any identity")]
    OAuthNotLinked,

    /// OAuth link revoked
    #[error("OAuth link has been revoked")]
    OAuthLinkRevoked,

    // OIDC-specific errors
    /// Missing ID token in response
    #[error("Missing ID token in OAuth response")]
    MissingIdToken,

    /// Invalid JWT signature
    #[error("Invalid JWT signature: {0}")]
    InvalidJwtSignature(String),

    /// JWT decode error
    #[error("Failed to decode JWT: {0}")]
    JwtDecodeError(String),

    /// Nonce mismatch
    #[error("Nonce mismatch: expected {expected}, got {got}")]
    NonceMismatch {
        /// Expected nonce value
        expected: String,
        /// Actual nonce value received
        got: String
    },

    /// Missing nonce in ID token
    #[error("Missing nonce in ID token")]
    MissingNonce,

    /// Invalid nonce (already used or expired)
    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),

    /// Issuer mismatch
    #[error("Issuer mismatch: expected {expected}, got {got}")]
    IssuerMismatch {
        /// Expected issuer
        expected: String,
        /// Actual issuer received
        got: String
    },

    /// Audience mismatch
    #[error("Audience mismatch: expected {expected}, got {got}")]
    AudienceMismatch {
        /// Expected audience
        expected: String,
        /// Actual audience received
        got: String
    },

    /// Token expired
    #[error("Token expired at {expired_at}, current time {current_time}")]
    TokenExpired {
        /// Unix timestamp when token expired
        expired_at: u64,
        /// Current unix timestamp
        current_time: u64
    },

    /// Token issued in future
    #[error("Token issued in future: iat={issued_at}, current_time={current_time}")]
    TokenIssuedInFuture {
        /// Unix timestamp when token was issued
        issued_at: u64,
        /// Current unix timestamp
        current_time: u64
    },

    /// JWKS key not found
    #[error("JWKS key not found: kid={kid}")]
    KeyNotFound {
        /// Key ID that was not found
        kid: String
    },

    /// Invalid algorithm
    #[error("Invalid algorithm: expected {expected}, got {got}")]
    InvalidAlgorithm {
        /// Expected algorithm
        expected: String,
        /// Actual algorithm received
        got: String
    },

    /// OIDC discovery failed
    #[error("OIDC discovery failed: {0}")]
    OidcDiscoveryFailed(String),

    /// Invalid base64 encoding
    #[error("Invalid base64 encoding: {0}")]
    InvalidBase64(String),

    /// Invalid RSA key
    #[error("Invalid RSA key: {0}")]
    InvalidRsaKey(String),

    /// Email mismatch (provider email changed)
    #[error("Email mismatch: stored={stored}, token={token}")]
    EmailMismatch {
        /// Email stored in database
        stored: String,
        /// Email from OAuth token
        token: String
    },

    /// Wallet signature invalid
    #[error("Wallet signature invalid: {0}")]
    WalletSignatureInvalid(String),

    /// Wallet address mismatch
    #[error("Wallet address mismatch: expected {expected}, recovered {recovered}")]
    WalletAddressMismatch {
        /// Expected wallet address
        expected: String,
        /// Recovered wallet address from signature
        recovered: String,
    },

    /// Wallet credential not found
    #[error("Wallet credential not found: {0}")]
    WalletCredentialNotFound(String),

    /// Wallet credential revoked
    #[error("Wallet credential revoked")]
    WalletCredentialRevoked,

    /// Credential not found
    #[error("Credential not found")]
    CredentialNotFound,

    /// Other error
    #[error("Other error: {0}")]
    Other(String),
}

/// Result type for Auth Methods operations
pub type Result<T> = std::result::Result<T, AuthMethodsError>;
