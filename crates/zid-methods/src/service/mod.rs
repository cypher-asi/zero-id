//! Auth Methods service implementation.

use crate::{errors::*, oauth::*, traits::AuthMethods, types::*};
use async_trait::async_trait;
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;
use zid_crypto::MachineKeyCapabilities;
use zid_crypto::{current_timestamp, hkdf_derive_32};
use zid_identity_core::{IdentityCore, MachineKey};
use zid_policy::{Operation, PolicyEngine};
use zid_storage::Storage;
use zeroize::Zeroizing;

// Sub-modules
mod email;
mod identity_creation;
mod machine;
mod mfa;
mod oauth;
mod wallet;

// Re-export identity creation types
pub use identity_creation::IdentityCreationResponse;

/// Column family names
/// Column family name for challenge storage
const CF_CHALLENGES: &str = "challenges";
/// Column family name for used nonces (replay prevention)
const CF_USED_NONCES: &str = "used_nonces";
/// Column family name for email/password credentials
const CF_AUTH_CREDENTIALS: &str = "auth_credentials";
/// Column family name for MFA secrets (encrypted)
const CF_MFA_SECRETS: &str = "mfa_secrets";
/// Column family name for OAuth state tracking (CSRF protection)
const CF_OAUTH_STATES: &str = "oauth_states";
/// Column family name for OAuth provider links
const CF_OAUTH_LINKS: &str = "oauth_links";
/// Column family name for OAuth link index by identity
const CF_OAUTH_LINKS_BY_IDENTITY: &str = "oauth_links_by_identity";
/// Column family name for wallet credentials
const CF_WALLET_CREDENTIALS: &str = "wallet_credentials";
/// Column family name for wallet credential index by identity
const CF_WALLET_CREDENTIALS_BY_IDENTITY: &str = "wallet_credentials_by_identity";
/// OAuth provider configuration
#[derive(Debug, Clone)]
pub struct OAuthProviderConfig {
    /// OAuth client ID
    pub client_id: String,
    /// OAuth client secret
    pub client_secret: String,
    /// OAuth redirect URI
    pub redirect_uri: String,
}

/// OAuth configurations for all providers
#[derive(Debug, Clone, Default)]
pub struct OAuthConfigs {
    /// Google OAuth configuration
    pub google: Option<OAuthProviderConfig>,
    /// X (Twitter) OAuth configuration
    pub x: Option<OAuthProviderConfig>,
    /// Epic Games OAuth configuration
    pub epic_games: Option<OAuthProviderConfig>,
}

/// Auth Methods service implementation
pub struct AuthMethodsService<I, P, S>
where
    I: IdentityCore,
    P: PolicyEngine,
    S: Storage,
{
    pub(self) identity_core: Arc<I>,
    pub(self) policy: Arc<P>,
    pub(self) storage: Arc<S>,
    pub(self) jwks_cache:
        Arc<tokio::sync::RwLock<std::collections::HashMap<OAuthProvider, JwksCacheEntry>>>,
    pub(self) oauth_configs: OAuthConfigs,
    pub(self) service_master_key: Zeroizing<[u8; 32]>,
}

impl<I, P, S> Drop for AuthMethodsService<I, P, S>
where
    I: IdentityCore,
    P: PolicyEngine,
    S: Storage,
{
    fn drop(&mut self) {
        // Zeroizing will automatically zero the key on drop
    }
}

impl<I, P, S> AuthMethodsService<I, P, S>
where
    I: IdentityCore,
    P: PolicyEngine,
    S: Storage,
{
    /// Create a new Auth Methods service
    pub fn new(
        identity_core: Arc<I>,
        policy: Arc<P>,
        storage: Arc<S>,
        service_master_key: [u8; 32],
    ) -> Self {
        Self::with_oauth_configs(
            identity_core,
            policy,
            storage,
            service_master_key,
            OAuthConfigs::default(),
        )
    }

    /// Create a new Auth Methods service with OAuth configurations
    pub fn with_oauth_configs(
        identity_core: Arc<I>,
        policy: Arc<P>,
        storage: Arc<S>,
        service_master_key: [u8; 32],
        oauth_configs: OAuthConfigs,
    ) -> Self {
        Self {
            identity_core,
            policy,
            storage,
            jwks_cache: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            oauth_configs,
            service_master_key: Zeroizing::new(service_master_key),
        }
    }

    /// Record a failed authentication attempt
    pub(self) async fn record_failed_attempt(&self, identity_id: Uuid) -> Result<()> {
        // Record the attempt with the policy engine for rate limiting
        self.policy
            .record_attempt(identity_id, Operation::Login, false)
            .await
            .map_err(AuthMethodsError::Policy)?;

        Ok(())
    }

    /// Derive per-user KEK for MFA secret encryption
    ///
    /// SECURITY: Combines service master key with identity_id to derive a unique KEK.
    /// This ensures that MFA secrets cannot be decrypted without the service master key.
    pub(self) fn derive_mfa_kek(&self, identity_id: Uuid) -> [u8; 32] {
        // Combine service master key and identity_id as IKM
        let mut ikm = Vec::with_capacity(48);
        ikm.extend_from_slice(&*self.service_master_key);
        ikm.extend_from_slice(identity_id.as_bytes());

        let info = b"cypher:auth:mfa-kek:v1";

        hkdf_derive_32(&ikm, info).expect("HKDF derivation failed")
    }

    /// Create a virtual machine for email-only authentication
    ///
    /// SECURITY NOTE: Virtual machines are a convenience feature for non-device-based auth.
    /// They use deterministic keys derived from service master key + identity_id.
    /// This provides security against external attackers but not against the service operator.
    /// Users should be encouraged to enroll real device-based machines for full security.
    pub(self) async fn create_virtual_machine(&self, identity_id: Uuid) -> Result<Uuid> {
        let (machine_id, signing_public_key, encryption_public_key) =
            self.derive_virtual_machine_keys(identity_id)?;

        // Check if virtual machine already exists
        if let Some(existing_vm) = self
            .storage
            .get::<Uuid, MachineKey>("machine_keys", &machine_id)
            .await?
        {
            // Update last_used_at timestamp
            let mut updated_vm = existing_vm;
            updated_vm.last_used_at = Some(current_timestamp());
            updated_vm.expires_at = Some(current_timestamp() + 86400);

            self.storage
                .put("machine_keys", &machine_id, &updated_vm)
                .await
                .map_err(AuthMethodsError::Storage)?;

            info!(
                "Reusing virtual machine {} for identity {}",
                machine_id, identity_id
            );
            return Ok(machine_id);
        }

        let virtual_machine = self.build_virtual_machine(
            identity_id,
            machine_id,
            signing_public_key,
            encryption_public_key,
        );

        // Store virtual machine directly
        self.storage
            .put(
                "machine_keys",
                &virtual_machine.machine_id,
                &virtual_machine,
            )
            .await
            .map_err(AuthMethodsError::Storage)?;

        info!(
            "Created virtual machine {} for identity {}",
            virtual_machine.machine_id, identity_id
        );

        Ok(virtual_machine.machine_id)
    }

    fn derive_virtual_machine_keys(&self, identity_id: Uuid) -> Result<(Uuid, [u8; 32], [u8; 32])> {
        use zid_crypto::{hkdf_derive_32, Ed25519KeyPair, X25519KeyPair};

        let machine_id_bytes =
            hkdf_derive_32(identity_id.as_bytes(), b"cypher:auth:virtual-machine-id:v1")?;
        let mut machine_id_array = [0u8; 16];
        machine_id_array.copy_from_slice(&machine_id_bytes[..16]);
        let machine_id = Uuid::from_bytes(machine_id_array);

        let mut ikm = Vec::with_capacity(48);
        ikm.extend_from_slice(&*self.service_master_key);
        ikm.extend_from_slice(identity_id.as_bytes());

        let signing_seed = hkdf_derive_32(&ikm, b"cypher:auth:virtual-machine-signing:v1")?;
        let signing_keypair = Ed25519KeyPair::from_seed(&signing_seed)?;

        let encryption_seed = hkdf_derive_32(&ikm, b"cypher:auth:virtual-machine-encryption:v1")?;
        let encryption_keypair = X25519KeyPair::from_seed(&encryption_seed)?;

        Ok((
            machine_id,
            signing_keypair.public_key().to_bytes(),
            *encryption_keypair.public_key().as_bytes(),
        ))
    }

    fn build_virtual_machine(
        &self,
        identity_id: Uuid,
        machine_id: Uuid,
        signing_public_key: [u8; 32],
        encryption_public_key: [u8; 32],
    ) -> MachineKey {
        MachineKey {
            machine_id,
            identity_id,
            namespace_id: identity_id,
            signing_public_key,
            encryption_public_key,
            capabilities: MachineKeyCapabilities::AUTHENTICATE,
            epoch: 0,
            created_at: current_timestamp(),
            expires_at: Some(current_timestamp() + 86400),
            last_used_at: Some(current_timestamp()),
            device_name: "Virtual Machine (Email+Password)".to_string(),
            device_platform: "web".to_string(),
            revoked: false,
            revoked_at: None,
            key_scheme: Default::default(),
            pq_signing_public_key: None,
            pq_encryption_public_key: None,
        }
    }
}

#[async_trait]
impl<I, P, S> AuthMethods for AuthMethodsService<I, P, S>
where
    I: IdentityCore + 'static,
    P: PolicyEngine + 'static,
    S: Storage + 'static,
{
    async fn create_challenge(&self, request: ChallengeRequest) -> Result<Challenge> {
        self.create_challenge(request).await
    }

    async fn authenticate_machine(
        &self,
        response: ChallengeResponse,
        ip_address: String,
        user_agent: String,
    ) -> Result<AuthResult> {
        self.authenticate_machine(response, ip_address, user_agent)
            .await
    }

    async fn authenticate_email(
        &self,
        request: EmailAuthRequest,
        ip_address: String,
        user_agent: String,
    ) -> Result<AuthResult> {
        self.authenticate_email(request, ip_address, user_agent)
            .await
    }

    async fn attach_email_credential(
        &self,
        identity_id: Uuid,
        email: String,
        password: String,
    ) -> Result<()> {
        self.attach_email_credential(identity_id, email, password)
            .await
    }

    async fn setup_mfa(&self, identity_id: Uuid) -> Result<MfaSetup> {
        self.setup_mfa(identity_id).await
    }

    async fn enable_mfa(&self, identity_id: Uuid, verification_code: String) -> Result<()> {
        self.enable_mfa(identity_id, verification_code).await
    }

    async fn disable_mfa(&self, identity_id: Uuid, mfa_code: String) -> Result<()> {
        self.disable_mfa(identity_id, mfa_code).await
    }

    async fn verify_mfa(&self, identity_id: Uuid, code: String) -> Result<bool> {
        self.verify_mfa(identity_id, code).await
    }

    async fn oauth_initiate(
        &self,
        identity_id: Uuid,
        provider: OAuthProvider,
    ) -> Result<OAuthInitiateResponse> {
        self.oauth_initiate(identity_id, provider).await
    }

    async fn oauth_initiate_login(&self, provider: OAuthProvider) -> Result<OAuthInitiateResponse> {
        self.oauth_initiate_login(provider).await
    }

    async fn oauth_complete(
        &self,
        identity_id: Uuid,
        request: OAuthCompleteRequest,
    ) -> Result<Uuid> {
        self.oauth_complete(identity_id, request).await
    }

    async fn authenticate_oauth(
        &self,
        request: OAuthCompleteRequest,
        ip_address: String,
        user_agent: String,
    ) -> Result<AuthResult> {
        self.authenticate_oauth(request, ip_address, user_agent)
            .await
    }

    async fn revoke_oauth_link(&self, identity_id: Uuid, provider: OAuthProvider) -> Result<()> {
        self.revoke_oauth_link(identity_id, provider).await
    }

    async fn authenticate_wallet(
        &self,
        signature: WalletSignature,
        ip_address: String,
        user_agent: String,
    ) -> Result<AuthResult> {
        self.authenticate_wallet(signature, ip_address, user_agent)
            .await
    }

    async fn attach_wallet_credential(
        &self,
        identity_id: Uuid,
        wallet_address: String,
        chain: String,
    ) -> Result<()> {
        self.attach_wallet_credential(identity_id, wallet_address, chain)
            .await
    }

    async fn revoke_wallet_credential(
        &self,
        identity_id: Uuid,
        wallet_address: String,
    ) -> Result<()> {
        self.revoke_wallet_credential(identity_id, wallet_address)
            .await
    }

    async fn list_credentials(
        &self,
        identity_id: Uuid,
    ) -> Result<Vec<crate::traits::CredentialInfo>> {
        info!("Listing credentials for identity {}", identity_id);

        let mut credentials = Vec::new();

        // List OAuth links
        for provider in [
            OAuthProvider::Google,
            OAuthProvider::X,
            OAuthProvider::EpicGames,
        ] {
            let identity_index_key = format!("{}:{}", identity_id, provider.as_str());
            if let Some(link_id) = self
                .storage
                .get::<String, Uuid>(CF_OAUTH_LINKS_BY_IDENTITY, &identity_index_key)
                .await?
            {
                let link_key = format!("{}:{}", provider.as_str(), link_id);
                if let Some(link) = self
                    .storage
                    .get::<String, OAuthLink>(CF_OAUTH_LINKS, &link_key)
                    .await?
                {
                    credentials.push(crate::traits::CredentialInfo {
                        credential_type: crate::traits::CredentialType::OAuth,
                        identifier: format!("{:?}", provider),
                        created_at: link.linked_at,
                        last_used_at: link.last_auth_at,
                        revoked: link.revoked,
                    });
                }
            }
        }

        info!(
            "Found {} credentials for identity {}",
            credentials.len(),
            identity_id
        );

        Ok(credentials)
    }
}
