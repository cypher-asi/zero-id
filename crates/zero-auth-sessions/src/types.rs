use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Session structure tracking an authenticated session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: Uuid,
    pub identity_id: Uuid,
    pub machine_id: Uuid,
    pub namespace_id: Uuid,
    pub token_family_id: Uuid,
    pub created_at: u64,
    pub expires_at: u64,
    pub last_activity_at: u64,
    pub revoked: bool,
    pub revoked_at: Option<u64>,
    pub revoked_reason: Option<String>,
}

/// Refresh token record stored in database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRecord {
    pub token_hash: [u8; 32],
    pub session_id: Uuid,
    pub machine_id: Uuid,
    pub token_family_id: Uuid,
    pub generation: u32,
    pub created_at: u64,
    pub expires_at: u64,
    pub used: bool,
    pub used_at: Option<u64>,
    pub revoked: bool,
    pub revoked_at: Option<u64>,
    pub revoked_reason: Option<String>,
}

/// JWT signing key for token issuance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtSigningKey {
    pub key_id: [u8; 16],
    pub epoch: u64,
    /// Encrypted Ed25519 seed (ciphertext includes 16-byte auth tag)
    pub private_key_encrypted: Vec<u8>,
    /// Nonce used for private key encryption (24 bytes for XChaCha20-Poly1305)
    pub private_key_nonce: [u8; 24],
    pub public_key: [u8; 32], // Ed25519 public key
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub status: KeyStatus,
}

/// Key status for rotation management
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum KeyStatus {
    Active = 0x01,
    Rotating = 0x02,
    Retired = 0x03,
}

/// JWT token claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    // Standard claims
    pub iss: String,      // Issuer
    pub sub: String,      // Subject (identity_id)
    pub aud: Vec<String>, // Audience
    pub iat: u64,         // Issued at
    pub exp: u64,         // Expiration
    pub nbf: u64,         // Not before
    pub jti: String,      // JWT ID

    // Custom claims
    pub machine_id: String,
    pub namespace_id: String,
    pub session_id: String,
    pub mfa_verified: bool,
    pub capabilities: Vec<String>,
    pub scope: Vec<String>,
    pub revocation_epoch: u64,
}

/// Session tokens returned to client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub session_id: Uuid,
    pub expires_in: u64,    // Seconds until access token expires
    pub token_type: String, // "Bearer"
}

/// JWKS response for public key distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<JsonWebKey>,
}

/// JSON Web Key for JWKS endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonWebKey {
    pub kty: String, // Key type: "OKP"
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>, // "sig"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>, // "EdDSA"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>, // Key ID
    pub crv: String, // Curve: "Ed25519"
    pub x: String,   // Base64url encoded public key
}

/// Token introspection response
///
/// Extends standard OAuth2 introspection with zero-auth specific claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenIntrospection {
    // Standard OAuth2 introspection fields
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    // zero-auth specific fields
    pub identity_id: Uuid,
    pub machine_id: Uuid,
    pub namespace_id: Uuid,
    pub session_id: Uuid,
    pub mfa_verified: bool,
    pub capabilities: Vec<String>,
    pub scopes: Vec<String>,
    pub revocation_epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Revocation event for integration subsystem
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEvent {
    pub event_type: RevocationEventType,
    pub identity_id: Uuid,
    pub session_id: Option<Uuid>,
    pub machine_id: Option<Uuid>,
    pub token_family_id: Option<Uuid>,
    pub timestamp: u64,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationEventType {
    SessionRevoked,
    AllSessionsRevoked,
    TokenFamilyRevoked,
    MachineRevoked,
    IdentityFrozen,
}

// Re-export current_timestamp from zero-auth-crypto
pub use zero_auth_crypto::current_timestamp;

/// Helper function to compute SHA256 hash
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Helper function to generate random bytes
pub fn generate_random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut bytes = [0u8; N];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Helper function to base64url encode (no padding)
pub fn base64_url_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(data)
}

/// Helper function to base64url decode
pub fn base64_url_decode(data: &str) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.decode(data).map_err(|e| e.to_string())
}
