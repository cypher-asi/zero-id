//! OAuth 2.0 and OIDC authentication methods.

use crate::{errors::*, oauth::*, types::*};
use tracing::{info, warn};
use uuid::Uuid;
use zero_auth_crypto::{blake3_hash, current_timestamp};
use zero_auth_identity_core::{Identity, IdentityCore, IdentityStatus};
use zero_auth_policy::{Operation, PolicyContext, PolicyEngine, Verdict};
use zero_auth_storage::Storage;

use super::{
    AuthMethodsService, OAuthProviderConfig, CF_OAUTH_LINKS, CF_OAUTH_LINKS_BY_IDENTITY,
    CF_OAUTH_STATES,
};

impl<I, P, S> AuthMethodsService<I, P, S>
where
    I: IdentityCore,
    P: PolicyEngine,
    S: Storage,
{
    /// Initiate OAuth flow for an identity.
    ///
    /// # Arguments
    ///
    /// * `identity_id` - The identity to link the OAuth provider to
    /// * `provider` - The OAuth provider to use
    ///
    /// # Returns
    ///
    /// OAuth initiate response with authorization URL and state
    pub(super) async fn oauth_initiate(
        &self,
        identity_id: Uuid,
        provider: OAuthProvider,
    ) -> Result<OAuthInitiateResponse> {
        info!(
            identity_id = %identity_id,
            provider = ?provider,
            "Initiating OAuth link flow"
        );

        // Verify identity exists and is not frozen
        let identity = self.identity_core.get_identity(identity_id).await?;
        if identity.status == IdentityStatus::Frozen {
            return Err(AuthMethodsError::IdentityFrozen {
                identity_id,
                reason: identity.frozen_reason,
            });
        }

        self.oauth_initiate_internal(Some(identity_id), provider)
            .await
    }

    /// Initiate OAuth login flow without requiring an existing identity.
    pub(super) async fn oauth_initiate_login(
        &self,
        provider: OAuthProvider,
    ) -> Result<OAuthInitiateResponse> {
        info!(provider = ?provider, "Initiating OAuth login flow");
        self.oauth_initiate_internal(None, provider).await
    }

    async fn oauth_initiate_internal(
        &self,
        identity_id: Option<Uuid>,
        provider: OAuthProvider,
    ) -> Result<OAuthInitiateResponse> {
        let (state, nonce, oauth_state) = self.build_oauth_state(identity_id, provider);

        self.storage
            .put(CF_OAUTH_STATES, &state, &oauth_state)
            .await?;

        let provider_config = self.get_provider_config(provider)?;
        let config = self.build_oauth_config(provider, provider_config)?;
        let auth_url = self.build_auth_url(provider, &config, &state, &nonce)?;

        info!(
            provider = ?provider,
            state_hash = %state_hash_for_log(&state),
            "OAuth flow initiated"
        );

        Ok(OAuthInitiateResponse { auth_url, state })
    }

    fn build_oauth_state(
        &self,
        identity_id: Option<Uuid>,
        provider: OAuthProvider,
    ) -> (String, String, OAuthState) {
        let state = hex::encode(rand::random::<[u8; 32]>());
        let nonce = generate_oidc_nonce();
        let oauth_state = OAuthState {
            state: state.clone(),
            nonce: nonce.clone(),
            identity_id,
            provider,
            created_at: current_timestamp(),
            expires_at: current_timestamp() + 600,
            used: false,
        };

        (state, nonce, oauth_state)
    }

    fn build_auth_url(
        &self,
        provider: OAuthProvider,
        config: &OAuthConfig,
        state: &str,
        nonce: &str,
    ) -> Result<String> {
        if provider == OAuthProvider::Google {
            build_auth_url_with_nonce(config, state, nonce)
        } else {
            OAuthClient::new().build_auth_url(config, state)
        }
    }

    /// Complete OAuth flow (for linking only, without authentication).
    ///
    /// # Arguments
    ///
    /// * `identity_id` - The identity to link to
    /// * `request` - OAuth complete request with authorization code and state
    ///
    /// # Returns
    ///
    /// The OAuth link ID
    pub(super) async fn oauth_complete(
        &self,
        identity_id: Uuid,
        request: OAuthCompleteRequest,
    ) -> Result<Uuid> {
        let link = self
            .oauth_complete_internal(&request, Some(identity_id))
            .await?;
        Ok(link.link_id)
    }

    /// Authenticate using OAuth.
    ///
    /// # Arguments
    ///
    /// * `request` - OAuth complete request with authorization code and state
    ///
    /// # Returns
    ///
    /// Authentication result with identity and machine information
    pub(super) async fn authenticate_oauth(
        &self,
        request: OAuthCompleteRequest,
        ip_address: String,
        user_agent: String,
    ) -> Result<AuthResult> {
        info!(
            provider = ?request.provider,
            "Authenticating with OAuth provider"
        );

        let link = self.oauth_complete_internal(&request, None).await?;
        let identity = self.load_active_identity(link.identity_id).await?;
        let machine_id = self.create_virtual_machine(link.identity_id).await?;
        let decision = self
            .evaluate_oauth_login(
                &identity,
                link.identity_id,
                machine_id,
                ip_address,
                user_agent,
            )
            .await?;

        if decision.verdict != Verdict::Allow {
            return Err(AuthMethodsError::PolicyDenied(decision.reason));
        }

        self.policy
            .record_attempt(link.identity_id, Operation::Login, true)
            .await?;

        info!(
            "OAuth authentication successful for identity {}",
            link.identity_id
        );

        Ok(self.build_oauth_auth_result(&identity, link.identity_id, machine_id))
    }

    /// Revoke an OAuth link for an identity.
    ///
    /// # Arguments
    ///
    /// * `identity_id` - The identity to revoke the link for
    /// * `provider` - The OAuth provider to revoke
    ///
    /// # Returns
    ///
    /// `Ok(())` if successful, error otherwise
    pub(super) async fn revoke_oauth_link(
        &self,
        identity_id: Uuid,
        provider: OAuthProvider,
    ) -> Result<()> {
        info!(
            "Revoking OAuth link for identity {} provider {:?}",
            identity_id, provider
        );

        // Find link by identity and provider
        let identity_index_key = format!("{}:{}", identity_id, provider.as_str());
        let link_id: Uuid = self
            .storage
            .get(CF_OAUTH_LINKS_BY_IDENTITY, &identity_index_key)
            .await?
            .ok_or_else(|| AuthMethodsError::Other("OAuth link not found".to_string()))?;

        // Get the link
        let link_key = format!("{}:{}", provider.as_str(), link_id);
        let mut link: OAuthLink = self
            .storage
            .get(CF_OAUTH_LINKS, &link_key)
            .await?
            .ok_or_else(|| AuthMethodsError::Other("OAuth link not found".to_string()))?;

        // Mark as revoked
        link.revoked = true;
        link.revoked_at = Some(current_timestamp());

        // Update link
        self.storage.put(CF_OAUTH_LINKS, &link_key, &link).await?;

        info!("OAuth link revoked for identity {}", identity_id);

        Ok(())
    }

    /// Internal helper to complete OAuth flow and create/update link.
    pub(super) async fn oauth_complete_internal(
        &self,
        request: &OAuthCompleteRequest,
        expected_identity_id: Option<Uuid>,
    ) -> Result<OAuthLink> {
        info!(
            provider = ?request.provider,
            state_hash = %state_hash_for_log(&request.state),
            "Completing OAuth flow"
        );

        // Step 1: Verify and consume state
        let oauth_state = self
            .verify_oauth_state(request, expected_identity_id)
            .await?;

        // Step 2: Get OAuth config
        let provider_config = self.get_provider_config(request.provider)?;
        let config = self.build_oauth_config(request.provider, provider_config)?;

        // Step 3: Exchange authorization code for tokens
        let token_response = self.exchange_oauth_code(&config, &request.code).await?;

        // Step 4: Get user info and create/update link
        let link = self
            .create_or_update_oauth_link(request, &oauth_state, &config, &token_response)
            .await?;

        Ok(link)
    }

    /// Verify and consume OAuth state (helper for oauth_complete_internal).
    async fn verify_oauth_state(
        &self,
        request: &OAuthCompleteRequest,
        expected_identity_id: Option<Uuid>,
    ) -> Result<OAuthState> {
        let oauth_state: OAuthState = self
            .storage
            .get(CF_OAUTH_STATES, &request.state)
            .await?
            .ok_or(AuthMethodsError::OAuthStateInvalid)?;

        if oauth_state.used {
            warn!(
                provider = ?request.provider,
                state_hash = %state_hash_for_log(&request.state),
                "OAuth state already used"
            );
            return Err(AuthMethodsError::OAuthStateInvalid);
        }

        if oauth_state.expires_at < current_timestamp() {
            warn!(
                provider = ?request.provider,
                state_hash = %state_hash_for_log(&request.state),
                "OAuth state expired"
            );
            let _ = self.storage.delete(CF_OAUTH_STATES, &request.state).await;
            return Err(AuthMethodsError::OAuthStateInvalid);
        }

        if oauth_state.provider != request.provider {
            warn!("OAuth provider mismatch");
            return Err(AuthMethodsError::OAuthStateInvalid);
        }

        if let Some(expected_identity_id) = expected_identity_id {
            if oauth_state.identity_id != Some(expected_identity_id) {
                warn!(
                    provider = ?request.provider,
                    state_hash = %state_hash_for_log(&request.state),
                    "OAuth state identity mismatch"
                );
                return Err(AuthMethodsError::OAuthStateInvalid);
            }
        }

        // SECURITY FIX: Delete state immediately after retrieving it
        self.storage.delete(CF_OAUTH_STATES, &request.state).await?;

        Ok(oauth_state)
    }

    /// Exchange authorization code for tokens (helper for oauth_complete_internal).
    async fn exchange_oauth_code(
        &self,
        config: &OAuthConfig,
        code: &str,
    ) -> Result<OAuthTokenResponse> {
        let oauth_client = OAuthClient::new();
        oauth_client.exchange_code(config, code).await
    }

    /// Create or update OAuth link (helper for oauth_complete_internal).
    async fn create_or_update_oauth_link(
        &self,
        request: &OAuthCompleteRequest,
        oauth_state: &OAuthState,
        config: &OAuthConfig,
        token_response: &OAuthTokenResponse,
    ) -> Result<OAuthLink> {
        let (provider_user_id, provider_email, email_verified, display_name) = self
            .get_oauth_user_info(request, oauth_state, config, token_response)
            .await?;

        let link_key = format!("{}:{}", request.provider.as_str(), provider_user_id);
        if let Some(updated_link) = self.update_existing_oauth_link(&link_key).await? {
            return Ok(updated_link);
        }

        let identity_id = self.require_oauth_identity_id(oauth_state)?;
        let link = self.build_new_oauth_link(
            request.provider,
            identity_id,
            provider_user_id,
            provider_email,
            email_verified,
            display_name,
        );

        self.store_oauth_link(&link_key, &link).await?;
        self.store_oauth_identity_index(identity_id, request.provider, link.link_id)
            .await?;

        info!(
            "OAuth link created: {} for identity {}",
            link.link_id, identity_id
        );

        Ok(link)
    }

    /// Get OAuth user info from provider (helper for create_or_update_oauth_link).
    async fn get_oauth_user_info(
        &self,
        request: &OAuthCompleteRequest,
        oauth_state: &OAuthState,
        config: &OAuthConfig,
        token_response: &OAuthTokenResponse,
    ) -> Result<(String, Option<String>, Option<bool>, Option<String>)> {
        if request.provider == OAuthProvider::Google {
            // Use OIDC ID token validation with JWKS caching
            let id_token = token_response
                .id_token
                .as_ref()
                .ok_or(AuthMethodsError::MissingIdToken)?;

            let claims = validate_id_token_with_cache(
                id_token,
                request.provider,
                &oauth_state.nonce,
                &config.client_id,
                &self.jwks_cache,
            )
            .await?;

            Ok((claims.sub, claims.email, claims.email_verified, claims.name))
        } else {
            // Fallback to OAuth 2.0 userinfo endpoint
            let oauth_client = OAuthClient::new();
            let user_info = oauth_client
                .get_user_info(config, &token_response.access_token)
                .await?;
            Ok((user_info.id, user_info.email, None, user_info.name))
        }
    }

    /// Get provider config from stored configs (helper).
    fn get_provider_config(&self, provider: OAuthProvider) -> Result<&OAuthProviderConfig> {
        let provider_config = match provider {
            OAuthProvider::Google => self.oauth_configs.google.as_ref(),
            OAuthProvider::X => self.oauth_configs.x.as_ref(),
            OAuthProvider::EpicGames => self.oauth_configs.epic_games.as_ref(),
        };

        provider_config.ok_or_else(|| {
            AuthMethodsError::Other(format!("OAuth provider {:?} not configured", provider))
        })
    }

    /// Build OAuth config from provider config (helper).
    fn build_oauth_config(
        &self,
        provider: OAuthProvider,
        provider_config: &OAuthProviderConfig,
    ) -> Result<OAuthConfig> {
        let config = match provider {
            OAuthProvider::Google => OAuthConfig::google(
                provider_config.client_id.clone(),
                provider_config.client_secret.clone(),
                provider_config.redirect_uri.clone(),
            ),
            OAuthProvider::X => OAuthConfig::x(
                provider_config.client_id.clone(),
                provider_config.client_secret.clone(),
                provider_config.redirect_uri.clone(),
            ),
            OAuthProvider::EpicGames => OAuthConfig::epic_games(
                provider_config.client_id.clone(),
                provider_config.client_secret.clone(),
                provider_config.redirect_uri.clone(),
            ),
        };

        Ok(config)
    }
}

include!("oauth_helpers.rs");
