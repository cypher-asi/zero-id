//! Auth Methods type definitions.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Challenge for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Unique challenge ID
    pub challenge_id: Uuid,

    /// Machine ID or entity ID this challenge is for
    pub entity_id: Uuid,

    /// Entity type (machine, wallet, email)
    pub entity_type: EntityType,

    /// Purpose of the challenge
    pub purpose: String,

    /// Audience (service URL)
    pub aud: String,

    /// Issued at timestamp
    pub iat: u64,

    /// Expiry timestamp
    pub exp: u64,

    /// Random nonce
    pub nonce: [u8; 32],

    /// Whether challenge has been used (replay protection)
    pub used: bool,
}

/// Entity type for challenges
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum EntityType {
    /// Machine key authentication
    Machine = 0x01,
    /// Wallet signature authentication
    Wallet = 0x02,
    /// Email + password authentication
    Email = 0x03,
}

/// Challenge response from client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// Challenge ID
    pub challenge_id: Uuid,

    /// Machine ID (for machine auth)
    pub machine_id: Uuid,

    /// Ed25519 signature of canonical challenge
    pub signature: Vec<u8>,

    /// Optional MFA code
    pub mfa_code: Option<String>,
}

/// Authentication result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    /// Identity ID
    pub identity_id: Uuid,

    /// Machine ID (always present, even for email auth via virtual machine)
    pub machine_id: Uuid,

    /// Namespace ID
    pub namespace_id: Uuid,

    /// Whether MFA was verified
    pub mfa_verified: bool,

    /// Authentication method used
    pub auth_method: AuthMethod,

    /// Warning message (e.g., "Enroll real device")
    pub warning: Option<String>,
}

// Re-export AuthMethod from policy crate to avoid duplication
pub use zero_auth_policy::AuthMethod;

/// Email credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailCredential {
    /// Identity ID
    pub identity_id: Uuid,

    /// Email address (lowercased)
    pub email: String,

    /// Argon2id password hash
    pub password_hash: String,

    /// Created timestamp
    pub created_at: u64,

    /// Last updated timestamp
    pub updated_at: u64,

    /// Email verified flag
    pub email_verified: bool,

    /// Verification token (if not verified)
    pub verification_token: Option<String>,
}

/// MFA secret (encrypted)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaSecret {
    /// Identity ID
    pub identity_id: Uuid,

    /// Encrypted TOTP secret (XChaCha20-Poly1305)
    pub encrypted_secret: Vec<u8>,

    /// Nonce for decryption
    pub nonce: [u8; 24],

    /// Backup codes (hashed)
    pub backup_codes: Vec<String>,

    /// Created timestamp
    pub created_at: u64,

    /// Whether MFA is enabled
    pub enabled: bool,
}

/// MFA setup response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaSetup {
    /// TOTP secret (base32 encoded)
    pub secret: String,

    /// QR code URL for authenticator apps
    pub qr_code_url: String,

    /// Backup codes (plaintext, shown once)
    pub backup_codes: Vec<String>,
}

/// Challenge request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    /// Machine ID to create challenge for
    pub machine_id: Uuid,

    /// Purpose of the challenge
    pub purpose: Option<String>,
}

/// Email authentication request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAuthRequest {
    /// Email address
    pub email: String,

    /// Password
    pub password: String,

    /// Machine ID (optional, for existing devices)
    pub machine_id: Option<Uuid>,

    /// MFA code (if MFA enabled)
    pub mfa_code: Option<String>,
}

/// OAuth provider
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum OAuthProvider {
    /// Google OAuth
    Google,
    /// X (formerly Twitter) OAuth
    X,
    /// Epic Games OAuth
    EpicGames,
}

impl OAuthProvider {
    /// Get provider name as string
    pub fn as_str(&self) -> &'static str {
        match self {
            OAuthProvider::Google => "google",
            OAuthProvider::X => "x",
            OAuthProvider::EpicGames => "epic_games",
        }
    }
}

/// OAuth/OIDC state for CSRF and replay protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthState {
    /// State parameter (random, for CSRF protection)
    pub state: String,

    /// Nonce parameter (random, for OIDC replay protection)
    pub nonce: String,

    /// Identity ID (if linking to existing identity)
    pub identity_id: Option<Uuid>,

    /// OAuth provider
    pub provider: OAuthProvider,

    /// Created timestamp
    pub created_at: u64,

    /// Expiry timestamp (10 minutes)
    pub expires_at: u64,

    /// Whether state has been used
    pub used: bool,
}

/// OAuth/OIDC link (stored credential)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthLink {
    /// Link ID
    pub link_id: Uuid,

    /// Identity ID
    pub identity_id: Uuid,

    /// OAuth provider
    pub provider: OAuthProvider,

    /// Provider's user ID (sub claim in OIDC)
    pub provider_user_id: String,

    /// Provider's email (if available)
    pub provider_email: Option<String>,

    /// Whether email is verified (OIDC only)
    pub email_verified: Option<bool>,

    /// Display name from provider
    pub display_name: Option<String>,

    /// When link was created
    pub linked_at: u64,

    /// Last authentication with this link
    pub last_auth_at: u64,

    /// Whether link is revoked
    pub revoked: bool,

    /// When link was revoked
    pub revoked_at: Option<u64>,
}

/// OAuth user info from provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    /// Provider's user ID
    pub id: String,

    /// Email address
    pub email: Option<String>,

    /// Display name
    pub name: Option<String>,

    /// Profile picture URL
    pub picture: Option<String>,
}

/// OAuth initiate response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthInitiateResponse {
    /// Authorization URL to redirect user to
    pub auth_url: String,

    /// State parameter for CSRF protection
    pub state: String,
}

/// OAuth complete request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCompleteRequest {
    /// OAuth provider
    pub provider: OAuthProvider,

    /// Authorization code from provider
    pub code: String,

    /// State parameter (must match stored state)
    pub state: String,
}

// ============================================================================
// OIDC Types
// ============================================================================

/// OIDC Configuration from discovery endpoint
/// From: https://accounts.google.com/.well-known/openid-configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfiguration {
    /// Issuer URL
    pub issuer: String,

    /// Authorization endpoint
    pub authorization_endpoint: String,

    /// Token endpoint
    pub token_endpoint: String,

    /// JWKS URI (JSON Web Key Set)
    pub jwks_uri: String,

    /// Supported response types
    pub response_types_supported: Vec<String>,

    /// Subject types supported
    pub subject_types_supported: Vec<String>,

    /// ID token signing algorithms supported
    pub id_token_signing_alg_values_supported: Vec<String>,

    /// Userinfo endpoint (optional, we prefer ID token claims)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
}

/// JSON Web Key Set from provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksKeySet {
    /// Array of JWK keys
    pub keys: Vec<JwksKey>,
}

impl JwksKeySet {
    /// Find key by Key ID (kid)
    pub fn find_key(&self, kid: &str) -> Option<&JwksKey> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }
}

/// Individual JSON Web Key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksKey {
    /// Key type (e.g., "RSA")
    pub kty: String,

    /// Key ID
    pub kid: Option<String>,

    /// Key use (e.g., "sig" for signature)
    #[serde(rename = "use")]
    pub use_: Option<String>,

    /// Algorithm (e.g., "RS256")
    pub alg: Option<String>,

    /// RSA modulus (base64url encoded)
    pub n: String,

    /// RSA public exponent (base64url encoded)
    pub e: String,
}

/// ID Token Claims (from JWT payload)
/// Standard OIDC claims: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer (provider URL)
    pub iss: String,

    /// Subject (provider's user ID)
    pub sub: String,

    /// Audience (our client ID)
    pub aud: String,

    /// Expiration time (Unix timestamp)
    pub exp: u64,

    /// Issued at time (Unix timestamp)
    pub iat: u64,

    /// Nonce (for replay protection)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Email address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Email verified flag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,

    /// Display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Profile picture URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,

    /// Given name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,

    /// Family name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
}

/// EVM wallet signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSignature {
    /// Challenge ID
    pub challenge_id: Uuid,

    /// Wallet address (0x...)
    pub wallet_address: String,

    /// SECP256k1 signature (65 bytes: r, s, v)
    pub signature: Vec<u8>,

    /// Optional MFA code
    pub mfa_code: Option<String>,
}

/// Wallet credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletCredential {
    /// Identity ID
    pub identity_id: Uuid,

    /// Wallet address (lowercased, with 0x prefix)
    pub wallet_address: String,

    /// Blockchain type (e.g., "ethereum", "polygon")
    pub chain: String,

    /// Created timestamp
    pub created_at: u64,

    /// Last used timestamp
    pub last_used_at: u64,

    /// Whether credential is revoked
    pub revoked: bool,

    /// When credential was revoked
    pub revoked_at: Option<u64>,
}