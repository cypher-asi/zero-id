//! Auth Methods type definitions.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Re-export Challenge and EntityType from zid-crypto to avoid duplication.
// The canonical definitions live in zid-crypto for use by both client and server.
pub use zid_crypto::{Challenge, EntityType};

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
pub use zid_policy::AuthMethod;

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

// OAuth types moved to oauth::types module
// Re-export them here for backward compatibility
pub use crate::oauth::types::{OAuthLink, OAuthState, OAuthUserInfo};

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

// OIDC types moved to oauth::oidc::types module
// Re-export them here for backward compatibility
pub use crate::oauth::oidc::{IdTokenClaims, JwksKey, JwksKeySet, OidcConfiguration};

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

/// Wallet blockchain types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletType {
    /// Ethereum mainnet (EVM, SECP256k1, EIP-191)
    Ethereum,
    /// Polygon (EVM, SECP256k1, EIP-191)
    Polygon,
    /// Arbitrum (EVM, SECP256k1, EIP-191)
    Arbitrum,
    /// Base (EVM, SECP256k1, EIP-191)
    Base,
    /// Solana (Ed25519)
    Solana,
}

impl WalletType {
    /// Get the signature scheme for this wallet type
    pub fn signature_scheme(&self) -> SignatureScheme {
        match self {
            Self::Ethereum | Self::Polygon | Self::Arbitrum | Self::Base => {
                SignatureScheme::Secp256k1Eip191
            }
            Self::Solana => SignatureScheme::Ed25519,
        }
    }

    /// Convert to auth method type
    pub fn to_auth_method_type(&self) -> AuthMethodType {
        match self {
            Self::Ethereum | Self::Polygon | Self::Arbitrum | Self::Base => AuthMethodType::WalletEvm,
            Self::Solana => AuthMethodType::WalletSolana,
        }
    }

    /// Get wallet type as string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ethereum => "ethereum",
            Self::Polygon => "polygon",
            Self::Arbitrum => "arbitrum",
            Self::Base => "base",
            Self::Solana => "solana",
        }
    }

    /// Check if this is an EVM-compatible wallet
    pub fn is_evm(&self) -> bool {
        matches!(
            self,
            Self::Ethereum | Self::Polygon | Self::Arbitrum | Self::Base
        )
    }
}

/// Signature scheme used by different wallet types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    /// Ethereum personal_sign (EIP-191) using SECP256k1
    Secp256k1Eip191,
    /// Ed25519 (Solana native)
    Ed25519,
}

/// Authentication method types for unified credential tracking
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethodType {
    /// Email + password
    Email = 0x01,
    /// Google OAuth
    OAuthGoogle = 0x02,
    /// X (Twitter) OAuth
    OAuthX = 0x03,
    /// Epic Games OAuth
    OAuthEpic = 0x04,
    /// EVM wallet (Ethereum, Polygon, Arbitrum, Base)
    WalletEvm = 0x10,
    /// Solana wallet
    WalletSolana = 0x11,
    /// Machine key (Neural Key flow)
    MachineKey = 0x20,
}

impl AuthMethodType {
    /// Get method type as string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::OAuthGoogle => "oauth_google",
            Self::OAuthX => "oauth_x",
            Self::OAuthEpic => "oauth_epic",
            Self::WalletEvm => "wallet_evm",
            Self::WalletSolana => "wallet_solana",
            Self::MachineKey => "machine_key",
        }
    }

    /// Check if this is an OAuth method
    pub fn is_oauth(&self) -> bool {
        matches!(
            self,
            Self::OAuthGoogle | Self::OAuthX | Self::OAuthEpic
        )
    }

    /// Check if this is a wallet method
    pub fn is_wallet(&self) -> bool {
        matches!(self, Self::WalletEvm | Self::WalletSolana)
    }
}

/// Record of linked authentication method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthLinkRecord {
    /// Identity ID
    pub identity_id: Uuid,
    /// Type of authentication method
    pub method_type: AuthMethodType,
    /// Method-specific identifier (email, provider:sub, wallet address)
    pub method_id: String,
    /// When this method was linked
    pub linked_at: u64,
    /// Whether this is the primary auth method (used for creation)
    pub is_primary: bool,
    /// Whether the method has been verified
    pub verified: bool,
    /// Last authentication timestamp
    pub last_used_at: Option<u64>,
}

/// Wallet credential with extended type awareness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletCredential {
    /// Identity ID
    pub identity_id: Uuid,

    /// Wallet type (ethereum, solana, etc.)
    #[serde(default = "default_wallet_type")]
    pub wallet_type: WalletType,

    /// Wallet address (lowercased, with 0x prefix for EVM, base58 for Solana)
    pub wallet_address: String,

    /// Public key bytes (stored for Solana where address = pubkey)
    #[serde(default)]
    pub public_key: Option<[u8; 32]>,

    /// Blockchain type (e.g., "ethereum", "polygon") - deprecated, use wallet_type
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

fn default_wallet_type() -> WalletType {
    WalletType::Ethereum
}
