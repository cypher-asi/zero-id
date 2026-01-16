//! Auth Methods trait definitions.

use crate::{
    errors::Result,
    types::*,
};
use async_trait::async_trait;
use uuid::Uuid;

/// Auth Methods subsystem trait
#[async_trait]
pub trait AuthMethods: Send + Sync {
    /// Create an authentication challenge
    ///
    /// Returns a structured challenge that the client must sign with their machine key.
    async fn create_challenge(&self, request: ChallengeRequest) -> Result<Challenge>;

    /// Authenticate with Machine Key challenge-response
    ///
    /// Verifies the signature on the challenge and returns an auth result.
    async fn authenticate_machine(&self, response: ChallengeResponse) -> Result<AuthResult>;

    /// Authenticate with email + password
    ///
    /// Supports both primary flow (with machine_id) and fallback flow (virtual machine).
    async fn authenticate_email(&self, request: EmailAuthRequest) -> Result<AuthResult>;

    /// Attach email credential to existing identity
    ///
    /// Allows adding email+password authentication to an existing identity.
    async fn attach_email_credential(
        &self,
        identity_id: Uuid,
        email: String,
        password: String,
    ) -> Result<()>;

    /// Setup MFA for identity
    ///
    /// Generates TOTP secret and backup codes, returns setup information.
    async fn setup_mfa(&self, identity_id: Uuid) -> Result<MfaSetup>;

    /// Enable MFA after verification
    ///
    /// Verifies the initial MFA code and enables MFA for the identity.
    async fn enable_mfa(&self, identity_id: Uuid, verification_code: String) -> Result<()>;

    /// Disable MFA
    ///
    /// Requires MFA code to disable (prevents unauthorized disabling).
    async fn disable_mfa(&self, identity_id: Uuid, mfa_code: String) -> Result<()>;

    /// Verify MFA code
    ///
    /// Checks TOTP code or backup code against stored secret.
    async fn verify_mfa(&self, identity_id: Uuid, code: String) -> Result<bool>;

    /// Initiate OAuth link flow
    ///
    /// Generates OAuth state and returns authorization URL.
    async fn oauth_initiate(
        &self,
        identity_id: Uuid,
        provider: OAuthProvider,
    ) -> Result<OAuthInitiateResponse>;

    /// Complete OAuth link flow
    ///
    /// Exchanges code for tokens, gets user info, and links to identity.
    async fn oauth_complete(&self, request: OAuthCompleteRequest) -> Result<Uuid>;

    /// Authenticate with OAuth
    ///
    /// Performs OAuth flow and returns auth result if account is linked.
    async fn authenticate_oauth(&self, request: OAuthCompleteRequest) -> Result<AuthResult>;

    /// Revoke OAuth link
    ///
    /// Removes OAuth credential from identity.
    async fn revoke_oauth_link(&self, identity_id: Uuid, provider: OAuthProvider) -> Result<()>;

    /// Authenticate with EVM wallet signature
    ///
    /// Verifies SECP256k1 signature and returns auth result.
    async fn authenticate_wallet(&self, signature: WalletSignature) -> Result<AuthResult>;

    /// Attach wallet credential to existing identity
    ///
    /// Links a wallet address to an identity.
    async fn attach_wallet_credential(
        &self,
        identity_id: Uuid,
        wallet_address: String,
        chain: String,
    ) -> Result<()>;

    /// Revoke wallet credential
    ///
    /// Removes wallet credential from identity.
    async fn revoke_wallet_credential(&self, identity_id: Uuid, wallet_address: String) -> Result<()>;

    /// List credentials for identity
    ///
    /// Returns all authentication credentials attached to an identity.
    async fn list_credentials(&self, identity_id: Uuid) -> Result<Vec<CredentialInfo>>;
}

/// Credential information for listing
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CredentialInfo {
    /// Credential type
    pub credential_type: CredentialType,
    /// Identifier (email, wallet address, or OAuth provider)
    pub identifier: String,
    /// Created timestamp
    pub created_at: u64,
    /// Last used timestamp
    pub last_used_at: u64,
    /// Whether credential is revoked
    pub revoked: bool,
}

/// Credential type
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    /// Email + password
    Email,
    /// OAuth provider
    OAuth,
    /// EVM wallet
    Wallet,
}
