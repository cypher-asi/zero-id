//! Auth Methods service implementation.

use crate::{
    challenge::*,
    errors::*,
    mfa::*,
    oauth::*,
    traits::AuthMethods,
    types::*,
    wallet::*,
};
use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;
use zero_auth_crypto::{generate_salt, hkdf_derive_32, hash_password, verify_password, verify_signature};
use zero_auth_identity_core::{IdentityCore, IdentityStatus, MachineKey};
use zero_auth_crypto::MachineKeyCapabilities;
use zero_auth_policy::{Operation, PolicyContext, PolicyEngine, Verdict};
use zero_auth_storage::Storage;

/// Column family names
/// Column family name for challenge storage
pub const CF_CHALLENGES: &str = "challenges";
/// Column family name for email/password credentials
pub const CF_AUTH_CREDENTIALS: &str = "auth_credentials";
/// Column family name for MFA secrets (encrypted)
pub const CF_MFA_SECRETS: &str = "mfa_secrets";
/// Column family name for OAuth state tracking (CSRF protection)
pub const CF_OAUTH_STATES: &str = "oauth_states";
/// Column family name for OAuth provider links
pub const CF_OAUTH_LINKS: &str = "oauth_links";
/// Column family name for OAuth link index by identity
pub const CF_OAUTH_LINKS_BY_IDENTITY: &str = "oauth_links_by_identity";
/// Column family name for wallet credentials
pub const CF_WALLET_CREDENTIALS: &str = "wallet_credentials";
/// Column family name for wallet credential index by identity
pub const CF_WALLET_CREDENTIALS_BY_IDENTITY: &str = "wallet_credentials_by_identity";
/// Column family name for JWKS key caching
pub const CF_JWKS_CACHE: &str = "jwks_cache";

/// Auth Methods service implementation
pub struct AuthMethodsService<I, P, S>
where
    I: IdentityCore,
    P: PolicyEngine,
    S: Storage,
{
    identity_core: Arc<I>,
    policy: Arc<P>,
    storage: Arc<S>,
    jwks_cache: Arc<tokio::sync::RwLock<std::collections::HashMap<OAuthProvider, JwksCacheEntry>>>,
}

impl<I, P, S> AuthMethodsService<I, P, S>
where
    I: IdentityCore,
    P: PolicyEngine,
    S: Storage,
{
    /// Create a new Auth Methods service
    pub fn new(identity_core: Arc<I>, policy: Arc<P>, storage: Arc<S>) -> Self {
        Self {
            identity_core,
            policy,
            storage,
            jwks_cache: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Record a failed authentication attempt
    async fn record_failed_attempt(&self, identity_id: Uuid) -> Result<()> {
        // Record the attempt with the policy engine for rate limiting
        self.policy
            .record_attempt(identity_id, Operation::Login, false)
            .await
            .map_err(AuthMethodsError::Policy)?;

        Ok(())
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
    }

    /// Derive per-user KEK for MFA secret encryption
    fn derive_mfa_kek(&self, identity_id: Uuid) -> [u8; 32] {
        // Use identity_id as ikm for deriving a unique KEK per user
        // Note: In production, this should use a service master key + identity_id
        // For now, we use identity_id directly as IKM
        let ikm = identity_id.as_bytes();
        let info = b"cypher:auth:mfa-kek:v1";

        hkdf_derive_32(ikm, info).expect("HKDF derivation failed")
    }

    /// Create a virtual machine for email-only authentication
    async fn create_virtual_machine(&self, identity_id: Uuid) -> Result<Uuid> {
        let virtual_machine = MachineKey {
            machine_id: Uuid::new_v4(),
            identity_id,
            namespace_id: identity_id, // Personal namespace
            signing_public_key: [0u8; 32],  // No keys for virtual machine
            encryption_public_key: [0u8; 32],  // No keys for virtual machine
            capabilities: MachineKeyCapabilities::AUTHENTICATE,  // Limited capabilities
            epoch: 0,
            created_at: Self::current_timestamp(),
            expires_at: Some(Self::current_timestamp() + 86400), // 24 hour expiry
            last_used_at: None,
            device_name: "Virtual Machine (Email+Password)".to_string(),
            device_platform: "web".to_string(),
            revoked: false,
            revoked_at: None,
        };

        // Store virtual machine directly (no authorization signature needed)
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
}

#[async_trait]
impl<I, P, S> AuthMethods for AuthMethodsService<I, P, S>
where
    I: IdentityCore + 'static,
    P: PolicyEngine + 'static,
    S: Storage + 'static,
{
    async fn create_challenge(&self, request: ChallengeRequest) -> Result<Challenge> {
        debug!("Creating challenge for machine {}", request.machine_id);

        // Verify machine exists and is not revoked
        let machine = self
            .identity_core
            .get_machine_key(request.machine_id)
            .await
            .map_err(|_| AuthMethodsError::MachineNotFound(request.machine_id))?;

        if machine.revoked {
            return Err(AuthMethodsError::MachineRevoked(request.machine_id));
        }

        // Check identity not frozen
        let identity = self
            .identity_core
            .get_identity(machine.identity_id)
            .await?;

        if identity.status == IdentityStatus::Frozen {
            return Err(AuthMethodsError::IdentityFrozen {
                identity_id: identity.identity_id,
                reason: identity.frozen_reason,
            });
        }

        // Generate challenge
        let challenge = generate_challenge(request.machine_id, request.purpose);

        // Store challenge with TTL
        self.storage
            .put(CF_CHALLENGES, &challenge.challenge_id, &challenge)
            .await?;

        info!("Challenge created: {}", challenge.challenge_id);

        Ok(challenge)
    }

    async fn authenticate_machine(&self, response: ChallengeResponse) -> Result<AuthResult> {
        info!(
            "Authenticating machine {} with challenge {}",
            response.machine_id, response.challenge_id
        );

        // Step 1: Get and validate challenge
        let mut challenge: Challenge = self
            .storage
            .get(CF_CHALLENGES, &response.challenge_id)
            .await?
            .ok_or(AuthMethodsError::ChallengeNotFound(response.challenge_id))?;

        // Check if already used (replay protection)
        if challenge.used {
            warn!(
                "Challenge {} already used (replay attack detected)",
                response.challenge_id
            );
            return Err(AuthMethodsError::ChallengeAlreadyUsed(
                response.challenge_id,
            ));
        }

        // Check expiry
        if is_challenge_expired(&challenge) {
            warn!("Challenge {} expired", response.challenge_id);
            return Err(AuthMethodsError::ChallengeExpired);
        }

        // Mark challenge as used atomically
        challenge.used = true;
        self.storage
            .put(CF_CHALLENGES, &challenge.challenge_id, &challenge)
            .await?;

        // Step 2: Get machine key and verify it's active
        let machine = self
            .identity_core
            .get_machine_key(response.machine_id)
            .await
            .map_err(|_| AuthMethodsError::MachineNotFound(response.machine_id))?;

        if machine.revoked {
            return Err(AuthMethodsError::MachineRevoked(response.machine_id));
        }

        // Step 3: Check identity frozen status
        let identity = self
            .identity_core
            .get_identity(machine.identity_id)
            .await?;

        if identity.status == IdentityStatus::Frozen {
            return Err(AuthMethodsError::IdentityFrozen {
                identity_id: identity.identity_id,
                reason: identity.frozen_reason,
            });
        }

        // Step 4: Verify signature
        let canonical_message = canonicalize_challenge(&challenge);

        verify_signature(
            &machine.signing_public_key,
            &canonical_message,
            &response
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| AuthMethodsError::InvalidSignature)?,
        )
        .map_err(|_| AuthMethodsError::InvalidSignature)?;

        // Step 5: Check MFA if provided
        let mfa_verified = if let Some(mfa_code) = response.mfa_code {
            self.verify_mfa(machine.identity_id, mfa_code).await?
        } else {
            false
        };

        // Step 6: Policy evaluation
        let decision = self
            .policy
            .evaluate(PolicyContext {
                identity_id: machine.identity_id,
                machine_id: Some(response.machine_id),
                namespace_id: machine.namespace_id,
                auth_method: zero_auth_policy::AuthMethod::MachineKey,
                mfa_verified,
                operation: Operation::Login,
                resource: None,
                ip_address: String::new(), // TODO: Get from request context
                user_agent: String::new(), // TODO: Get from request context
                timestamp: Self::current_timestamp(),
                reputation_score: 0,
                recent_failed_attempts: 0,
            })
            .await?;

        if decision.verdict != Verdict::Allow {
            return Err(AuthMethodsError::PolicyDenied(decision.reason));
        }

        // Step 7: Record successful attempt
        self.policy
            .record_attempt(machine.identity_id, Operation::Login, true)
            .await?;

        info!(
            "Machine authentication successful for identity {}",
            machine.identity_id
        );

        Ok(AuthResult {
            identity_id: machine.identity_id,
            machine_id: response.machine_id,
            namespace_id: machine.namespace_id,
            mfa_verified,
            auth_method: AuthMethod::MachineKey,
            warning: None,
        })
    }

    async fn authenticate_email(&self, request: EmailAuthRequest) -> Result<AuthResult> {
        info!("Authenticating with email: {}", request.email);

        // Step 1: Get credential and verify password
        let email_lower = request.email.to_lowercase();
        let credential: EmailCredential = self
            .storage
            .get(CF_AUTH_CREDENTIALS, &email_lower)
            .await?
            .ok_or(AuthMethodsError::EmailCredentialNotFound(
                request.email.clone(),
            ))?;

        if verify_password(request.password.as_bytes(), &credential.password_hash).is_err() {
            self.record_failed_attempt(credential.identity_id).await?;
            return Err(AuthMethodsError::InvalidCredentials);
        }

        // Step 2: Get identity and check MFA
        let identity = self
            .identity_core
            .get_identity(credential.identity_id)
            .await?;

        // Check identity not frozen
        if identity.status == IdentityStatus::Frozen {
            return Err(AuthMethodsError::IdentityFrozen {
                identity_id: identity.identity_id,
                reason: identity.frozen_reason,
            });
        }

        // Verify MFA if enabled
        let mfa_verified = if let Some(mfa_secret) = self
            .storage
            .get::<Uuid, MfaSecret>(CF_MFA_SECRETS, &credential.identity_id)
            .await?
        {
            if mfa_secret.enabled {
                let code = request
                    .mfa_code
                    .ok_or(AuthMethodsError::MfaRequired)?;
                if !self.verify_mfa(credential.identity_id, code).await? {
                    return Err(AuthMethodsError::InvalidMfaCode);
                }
                true
            } else {
                false
            }
        } else {
            false
        };

        // Step 3: Determine or create machine_id
        let (final_machine_id, warning) = if let Some(mid) = request.machine_id {
            // Primary flow: Verify machine belongs to identity
            let machine = self
                .identity_core
                .get_machine_key(mid)
                .await
                .map_err(|_| AuthMethodsError::MachineNotFound(mid))?;

            if machine.identity_id != credential.identity_id {
                return Err(AuthMethodsError::MachineNotOwned {
                    machine_id: mid,
                    identity_id: credential.identity_id,
                });
            }

            if machine.revoked {
                return Err(AuthMethodsError::MachineRevoked(mid));
            }

            (mid, None)
        } else {
            // Fallback flow: Check if any active machines exist
            let active_machines = self
                .identity_core
                .list_machines(credential.identity_id, identity.identity_id)
                .await?;

            if !active_machines.is_empty() {
                return Err(AuthMethodsError::MachineIdRequired {
                    hint: "Use machine_id from existing device".to_string(),
                });
            }

            // Create virtual machine
            let vm_id = self.create_virtual_machine(credential.identity_id).await?;
            (
                vm_id,
                Some("Virtual machine created. Please enroll a real device.".to_string()),
            )
        };

        // Step 4: Policy evaluation
        let decision = self
            .policy
            .evaluate(PolicyContext {
                identity_id: credential.identity_id,
                machine_id: Some(final_machine_id),
                namespace_id: identity.identity_id, // Personal namespace
                auth_method: zero_auth_policy::AuthMethod::EmailPassword,
                mfa_verified,
                operation: Operation::Login,
                resource: None,
                ip_address: String::new(), // TODO: Get from request context
                user_agent: String::new(), // TODO: Get from request context
                timestamp: Self::current_timestamp(),
                reputation_score: 0,
                recent_failed_attempts: 0,
            })
            .await?;

        if decision.verdict != Verdict::Allow {
            return Err(AuthMethodsError::PolicyDenied(decision.reason));
        }

        // Step 5: Record successful attempt
        self.policy
            .record_attempt(credential.identity_id, Operation::Login, true)
            .await?;

        info!(
            "Email authentication successful for identity {}",
            credential.identity_id
        );

        Ok(AuthResult {
            identity_id: credential.identity_id,
            machine_id: final_machine_id,
            namespace_id: identity.identity_id,
            mfa_verified,
            auth_method: AuthMethod::EmailPassword,
            warning,
        })
    }

    async fn attach_email_credential(
        &self,
        identity_id: Uuid,
        email: String,
        password: String,
    ) -> Result<()> {
        info!("Attaching email credential for identity {}", identity_id);

        // Verify identity exists
        let _identity = self.identity_core.get_identity(identity_id).await?;

        // Check if email already exists
        let email_lower = email.to_lowercase();
        if self
            .storage
            .exists(CF_AUTH_CREDENTIALS, &email_lower)
            .await?
        {
            return Err(AuthMethodsError::Other(
                "Email already registered".to_string(),
            ));
        }

        // Hash password with Argon2id
        let salt = generate_salt();
        let password_hash = hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthMethodsError::PasswordHash(e.to_string()))?;

        // Create credential
        let credential = EmailCredential {
            identity_id,
            email: email_lower.clone(),
            password_hash,
            created_at: Self::current_timestamp(),
            updated_at: Self::current_timestamp(),
            email_verified: false,
            verification_token: None,
        };

        // Store credential
        self.storage
            .put(CF_AUTH_CREDENTIALS, &email_lower, &credential)
            .await?;

        info!(
            "Email credential attached for identity {}",
            identity_id
        );

        Ok(())
    }

    async fn setup_mfa(&self, identity_id: Uuid) -> Result<MfaSetup> {
        info!("Setting up MFA for identity {}", identity_id);

        // Verify identity exists
        let _identity = self.identity_core.get_identity(identity_id).await?;

        // Check if MFA already enabled
        if let Some(mfa_secret) = self
            .storage
            .get::<Uuid, MfaSecret>(CF_MFA_SECRETS, &identity_id)
            .await?
        {
            if mfa_secret.enabled {
                return Err(AuthMethodsError::MfaAlreadyEnabled(identity_id));
            }
        }

        // Generate MFA setup
        let account_name = format!("user-{}", identity_id);
        let setup = generate_mfa_setup("ZeroAuth", &account_name)?;

        // Encrypt secret with per-user KEK
        let kek = self.derive_mfa_kek(identity_id);
        let (encrypted_secret, nonce) = encrypt_mfa_secret_data(&setup.secret, &kek, &identity_id)?;

        // Hash backup codes for storage
        let backup_code_hashes: Vec<String> = setup
            .backup_codes
            .iter()
            .map(|code| hash_backup_code(code))
            .collect();

        // Store encrypted MFA secret (not yet enabled)
        let mfa_secret = MfaSecret {
            identity_id,
            encrypted_secret,
            nonce,
            backup_codes: backup_code_hashes,
            created_at: Self::current_timestamp(),
            enabled: false, // Not enabled until verified
        };

        self.storage
            .put(CF_MFA_SECRETS, &identity_id, &mfa_secret)
            .await?;

        info!("MFA setup completed for identity {}", identity_id);

        Ok(setup)
    }

    async fn enable_mfa(&self, identity_id: Uuid, verification_code: String) -> Result<()> {
        info!("Enabling MFA for identity {}", identity_id);

        // Get MFA secret
        let mut mfa_secret: MfaSecret = self
            .storage
            .get(CF_MFA_SECRETS, &identity_id)
            .await?
            .ok_or(AuthMethodsError::MfaNotEnabled(identity_id))?;

        if mfa_secret.enabled {
            return Err(AuthMethodsError::MfaAlreadyEnabled(identity_id));
        }

        // Decrypt secret
        let kek = self.derive_mfa_kek(identity_id);
        let secret = decrypt_mfa_secret_data(&mfa_secret.encrypted_secret, &mfa_secret.nonce, &kek, &identity_id)?;

        // Verify the code
        if !verify_totp_code(&secret, &verification_code)? {
            return Err(AuthMethodsError::InvalidMfaCode);
        }

        // Enable MFA
        mfa_secret.enabled = true;
        self.storage
            .put(CF_MFA_SECRETS, &identity_id, &mfa_secret)
            .await?;

        info!("MFA enabled for identity {}", identity_id);

        Ok(())
    }

    async fn disable_mfa(&self, identity_id: Uuid, mfa_code: String) -> Result<()> {
        info!("Disabling MFA for identity {}", identity_id);

        // Verify MFA code before disabling
        if !self.verify_mfa(identity_id, mfa_code).await? {
            return Err(AuthMethodsError::InvalidMfaCode);
        }

        // Delete MFA secret
        self.storage
            .delete(CF_MFA_SECRETS, &identity_id)
            .await?;

        info!("MFA disabled for identity {}", identity_id);

        Ok(())
    }

    async fn verify_mfa(&self, identity_id: Uuid, code: String) -> Result<bool> {
        // Get MFA secret
        let mfa_secret: MfaSecret = self
            .storage
            .get(CF_MFA_SECRETS, &identity_id)
            .await?
            .ok_or(AuthMethodsError::MfaNotEnabled(identity_id))?;

        if !mfa_secret.enabled {
            return Err(AuthMethodsError::MfaNotEnabled(identity_id));
        }

        // Decrypt secret
        let kek = self.derive_mfa_kek(identity_id);
        let secret = decrypt_mfa_secret_data(&mfa_secret.encrypted_secret, &mfa_secret.nonce, &kek, &identity_id)?;

        // Try TOTP verification first
        if verify_totp_code(&secret, &code)? {
            return Ok(true);
        }

        // Try backup codes
        let code_hash = hash_backup_code(&code);
        if mfa_secret.backup_codes.contains(&code_hash) {
            // TODO: Remove used backup code from storage
            return Ok(true);
        }

        Ok(false)
    }

    async fn oauth_initiate(
        &self,
        identity_id: Uuid,
        provider: OAuthProvider,
    ) -> Result<OAuthInitiateResponse> {
        info!("Initiating OAuth flow for identity {} with provider {:?}", identity_id, provider);

        // Verify identity exists and is not frozen
        let identity = self.identity_core.get_identity(identity_id).await?;
        if identity.status == IdentityStatus::Frozen {
            return Err(AuthMethodsError::IdentityFrozen {
                identity_id,
                reason: identity.frozen_reason,
            });
        }

        // Generate state and nonce for CSRF and replay protection
        let state = hex::encode(rand::random::<[u8; 32]>());
        let nonce = generate_oidc_nonce();

        // Create OAuth state record
        let oauth_state = OAuthState {
            state: state.clone(),
            nonce: nonce.clone(),
            identity_id: Some(identity_id),
            provider,
            created_at: Self::current_timestamp(),
            expires_at: Self::current_timestamp() + 600, // 10 minutes
            used: false,
        };

        // Store state
        self.storage
            .put(CF_OAUTH_STATES, &state, &oauth_state)
            .await?;

        // Build OAuth config (in production, these would come from environment/config)
        let config = match provider {
            OAuthProvider::Google => OAuthConfig::google(
                "client_id".to_string(), // TODO: Get from config
                "client_secret".to_string(),
                "http://localhost:8080/callback".to_string(),
            ),
            OAuthProvider::X => OAuthConfig::x(
                "client_id".to_string(),
                "client_secret".to_string(),
                "http://localhost:8080/callback".to_string(),
            ),
            OAuthProvider::EpicGames => OAuthConfig::epic_games(
                "client_id".to_string(),
                "client_secret".to_string(),
                "http://localhost:8080/callback".to_string(),
            ),
        };

        // Build authorization URL with nonce (for OIDC providers)
        let auth_url = if provider == OAuthProvider::Google {
            build_auth_url_with_nonce(&config, &state, &nonce)?
        } else {
            OAuthClient::new().build_auth_url(&config, &state)?
        };

        info!("OAuth flow initiated with state {}", state);

        Ok(OAuthInitiateResponse { auth_url, state })
    }

    async fn oauth_complete(&self, request: OAuthCompleteRequest) -> Result<Uuid> {
        info!("Completing OAuth flow with state {}", request.state);

        // Step 1: Verify and consume state
        let mut oauth_state: OAuthState = self
            .storage
            .get(CF_OAUTH_STATES, &request.state)
            .await?
            .ok_or(AuthMethodsError::OAuthStateInvalid)?;

        if oauth_state.used {
            warn!("OAuth state {} already used", request.state);
            return Err(AuthMethodsError::OAuthStateInvalid);
        }

        if oauth_state.expires_at < Self::current_timestamp() {
            warn!("OAuth state {} expired", request.state);
            return Err(AuthMethodsError::OAuthStateInvalid);
        }

        if oauth_state.provider != request.provider {
            warn!("OAuth provider mismatch");
            return Err(AuthMethodsError::OAuthStateInvalid);
        }

        // Mark state as used
        oauth_state.used = true;
        self.storage
            .put(CF_OAUTH_STATES, &request.state, &oauth_state)
            .await?;

        // Step 2: Build OAuth config
        let config = match request.provider {
            OAuthProvider::Google => OAuthConfig::google(
                "client_id".to_string(),
                "client_secret".to_string(),
                "http://localhost:8080/callback".to_string(),
            ),
            OAuthProvider::X => OAuthConfig::x(
                "client_id".to_string(),
                "client_secret".to_string(),
                "http://localhost:8080/callback".to_string(),
            ),
            OAuthProvider::EpicGames => OAuthConfig::epic_games(
                "client_id".to_string(),
                "client_secret".to_string(),
                "http://localhost:8080/callback".to_string(),
            ),
        };

        // Step 3: Exchange authorization code for tokens
        let oauth_client = OAuthClient::new();
        let token_response = oauth_client.exchange_code(&config, &request.code).await?;

        // Step 4: Get user info (OIDC or OAuth 2.0)
        let (provider_user_id, provider_email, email_verified, display_name): (String, Option<String>, Option<bool>, Option<String>) = 
            if request.provider == OAuthProvider::Google {
                // Use OIDC ID token validation with JWKS caching
                let id_token = token_response.id_token.as_ref()
                    .ok_or(AuthMethodsError::MissingIdToken)?;

                let claims = validate_id_token_with_cache(
                    id_token,
                    request.provider,
                    &oauth_state.nonce,
                    &config.client_id,
                    &self.jwks_cache,
                ).await?;

                (
                    claims.sub,
                    claims.email,
                    claims.email_verified,
                    claims.name,
                )
            } else {
                // Fallback to OAuth 2.0 userinfo endpoint
                let user_info = oauth_client.get_user_info(&config, &token_response.access_token).await?;
                (user_info.id, user_info.email, None, user_info.name)
            };

        // Step 5: Check if link already exists
        let link_key = format!("{}:{}", request.provider.as_str(), provider_user_id);
        let existing_link: Option<OAuthLink> = self
            .storage
            .get(CF_OAUTH_LINKS, &link_key)
            .await?;

        if let Some(existing_link) = existing_link {
            if existing_link.revoked {
                return Err(AuthMethodsError::Other("OAuth link was revoked".to_string()));
            }

            // Update last_auth_at
            let mut updated_link = existing_link.clone();
            updated_link.last_auth_at = Self::current_timestamp();
            self.storage
                .put(CF_OAUTH_LINKS, &link_key, &updated_link)
                .await?;

            info!("OAuth link already exists for identity {}", existing_link.identity_id);
            return Ok(updated_link.link_id);
        }

        // Step 6: Create new link
        let identity_id = oauth_state.identity_id
            .ok_or_else(|| AuthMethodsError::Other("No identity_id in OAuth state".to_string()))?;

        let link = OAuthLink {
            link_id: Uuid::new_v4(),
            identity_id,
            provider: request.provider,
            provider_user_id: provider_user_id.clone(),
            provider_email,
            email_verified,
            display_name,
            linked_at: Self::current_timestamp(),
            last_auth_at: Self::current_timestamp(),
            revoked: false,
            revoked_at: None,
        };

        // Store link
        self.storage
            .put(CF_OAUTH_LINKS, &link_key, &link)
            .await?;

        // Store identity index
        let identity_index_key = format!("{}:{}", identity_id, request.provider.as_str());
        self.storage
            .put(CF_OAUTH_LINKS_BY_IDENTITY, &identity_index_key, &link.link_id)
            .await?;

        info!("OAuth link created: {} for identity {}", link.link_id, identity_id);

        Ok(link.link_id)
    }

    async fn authenticate_oauth(&self, request: OAuthCompleteRequest) -> Result<AuthResult> {
        info!("Authenticating with OAuth provider {:?}", request.provider);

        // Step 1: Complete OAuth flow (this creates or updates the link)
        let link_id = self.oauth_complete(request.clone()).await?;

        // Step 2: Get the link to find identity_id
        let link_key = format!("{}:{}", request.provider.as_str(), link_id);
        let link: OAuthLink = self
            .storage
            .get(CF_OAUTH_LINKS, &link_key)
            .await?
            .ok_or_else(|| AuthMethodsError::Other("OAuth link not found after creation".to_string()))?;

        // Step 3: Verify identity is not frozen
        let identity = self.identity_core.get_identity(link.identity_id).await?;
        if identity.status == IdentityStatus::Frozen {
            return Err(AuthMethodsError::IdentityFrozen {
                identity_id: link.identity_id,
                reason: identity.frozen_reason,
            });
        }

        // Step 4: Create or get virtual machine for OAuth authentication
        let machine_id = self.create_virtual_machine(link.identity_id).await?;

        // Step 5: Policy evaluation
        let decision = self
            .policy
            .evaluate(PolicyContext {
                identity_id: link.identity_id,
                machine_id: Some(machine_id),
                namespace_id: identity.identity_id,
                auth_method: zero_auth_policy::AuthMethod::OAuth,
                mfa_verified: false,
                operation: Operation::Login,
                resource: None,
                ip_address: String::new(),
                user_agent: String::new(),
                timestamp: Self::current_timestamp(),
                reputation_score: 0,
                recent_failed_attempts: 0,
            })
            .await?;

        if decision.verdict != Verdict::Allow {
            return Err(AuthMethodsError::PolicyDenied(decision.reason));
        }

        // Step 6: Record successful attempt
        self.policy
            .record_attempt(link.identity_id, Operation::Login, true)
            .await?;

        info!("OAuth authentication successful for identity {}", link.identity_id);

        Ok(AuthResult {
            identity_id: link.identity_id,
            machine_id,
            namespace_id: identity.identity_id,
            mfa_verified: false,
            auth_method: AuthMethod::OAuth,
            warning: Some("Consider enrolling a real device for enhanced security".to_string()),
        })
    }

    async fn revoke_oauth_link(&self, identity_id: Uuid, provider: OAuthProvider) -> Result<()> {
        info!("Revoking OAuth link for identity {} provider {:?}", identity_id, provider);

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
        link.revoked_at = Some(Self::current_timestamp());

        // Update link
        self.storage
            .put(CF_OAUTH_LINKS, &link_key, &link)
            .await?;

        info!("OAuth link revoked for identity {}", identity_id);

        Ok(())
    }

    async fn authenticate_wallet(&self, signature: WalletSignature) -> Result<AuthResult> {
        info!("Authenticating wallet {}", signature.wallet_address);

        // Step 1: Get and validate challenge
        let mut challenge: Challenge = self
            .storage
            .get(CF_CHALLENGES, &signature.challenge_id)
            .await?
            .ok_or(AuthMethodsError::ChallengeNotFound(signature.challenge_id))?;

        if challenge.used {
            warn!("Challenge {} already used", signature.challenge_id);
            return Err(AuthMethodsError::ChallengeAlreadyUsed(signature.challenge_id));
        }

        if is_challenge_expired(&challenge) {
            warn!("Challenge {} expired", signature.challenge_id);
            return Err(AuthMethodsError::ChallengeExpired);
        }

        // Mark challenge as used
        challenge.used = true;
        self.storage
            .put(CF_CHALLENGES, &challenge.challenge_id, &challenge)
            .await?;

        // Step 2: Verify wallet signature
        let sig_bytes: [u8; 65] = signature.signature.as_slice()
            .try_into()
            .map_err(|_| AuthMethodsError::WalletSignatureInvalid("Invalid signature length".to_string()))?;

        verify_wallet_signature(&challenge, &signature.wallet_address, &sig_bytes)?;

        // Step 3: Get wallet credential
        let wallet_address_lower = signature.wallet_address.to_lowercase();
        let credential: WalletCredential = self
            .storage
            .get(CF_WALLET_CREDENTIALS, &wallet_address_lower)
            .await?
            .ok_or_else(|| AuthMethodsError::Other("Wallet not linked to any identity".to_string()))?;

        if credential.revoked {
            return Err(AuthMethodsError::Other("Wallet credential is revoked".to_string()));
        }

        // Step 4: Check identity frozen status
        let identity = self.identity_core.get_identity(credential.identity_id).await?;
        if identity.status == IdentityStatus::Frozen {
            return Err(AuthMethodsError::IdentityFrozen {
                identity_id: credential.identity_id,
                reason: identity.frozen_reason,
            });
        }

        // Step 5: Check MFA if provided
        let mfa_verified = if let Some(mfa_code) = signature.mfa_code {
            self.verify_mfa(credential.identity_id, mfa_code).await?
        } else {
            false
        };

        // Step 6: Create or get virtual machine for wallet authentication
        let machine_id = self.create_virtual_machine(credential.identity_id).await?;

        // Step 7: Policy evaluation
        let decision = self
            .policy
            .evaluate(PolicyContext {
                identity_id: credential.identity_id,
                machine_id: Some(machine_id),
                namespace_id: identity.identity_id,
                auth_method: zero_auth_policy::AuthMethod::EvmWallet,
                mfa_verified,
                operation: Operation::Login,
                resource: None,
                ip_address: String::new(),
                user_agent: String::new(),
                timestamp: Self::current_timestamp(),
                reputation_score: 0,
                recent_failed_attempts: 0,
            })
            .await?;

        if decision.verdict != Verdict::Allow {
            return Err(AuthMethodsError::PolicyDenied(decision.reason));
        }

        // Step 8: Update last_used_at
        let mut updated_credential = credential.clone();
        updated_credential.last_used_at = Self::current_timestamp();
        self.storage
            .put(CF_WALLET_CREDENTIALS, &wallet_address_lower, &updated_credential)
            .await?;

        // Step 9: Record successful attempt
        self.policy
            .record_attempt(credential.identity_id, Operation::Login, true)
            .await?;

        info!("Wallet authentication successful for identity {}", credential.identity_id);

        Ok(AuthResult {
            identity_id: credential.identity_id,
            machine_id,
            namespace_id: identity.identity_id,
            mfa_verified,
            auth_method: AuthMethod::EvmWallet,
            warning: Some("Consider enrolling a real device for enhanced security".to_string()),
        })
    }

    async fn attach_wallet_credential(
        &self,
        identity_id: Uuid,
        wallet_address: String,
        chain: String,
    ) -> Result<()> {
        info!("Attaching wallet credential {} for identity {}", wallet_address, identity_id);

        // Verify identity exists
        let _identity = self.identity_core.get_identity(identity_id).await?;

        // Normalize wallet address
        let wallet_address_lower = wallet_address.to_lowercase();

        // Check if wallet already exists
        if self
            .storage
            .exists(CF_WALLET_CREDENTIALS, &wallet_address_lower)
            .await?
        {
            return Err(AuthMethodsError::Other("Wallet already linked to an identity".to_string()));
        }

        // Create credential
        let credential = WalletCredential {
            identity_id,
            wallet_address: wallet_address_lower.clone(),
            chain,
            created_at: Self::current_timestamp(),
            last_used_at: Self::current_timestamp(),
            revoked: false,
            revoked_at: None,
        };

        // Store credential
        self.storage
            .put(CF_WALLET_CREDENTIALS, &wallet_address_lower, &credential)
            .await?;

        // Store identity index
        let identity_index_key = format!("{}:{}", identity_id, wallet_address_lower);
        self.storage
            .put(CF_WALLET_CREDENTIALS_BY_IDENTITY, &identity_index_key, &())
            .await?;

        info!("Wallet credential attached for identity {}", identity_id);

        Ok(())
    }

    async fn revoke_wallet_credential(&self, identity_id: Uuid, wallet_address: String) -> Result<()> {
        info!("Revoking wallet credential {} for identity {}", wallet_address, identity_id);

        let wallet_address_lower = wallet_address.to_lowercase();

        // Get credential
        let mut credential: WalletCredential = self
            .storage
            .get(CF_WALLET_CREDENTIALS, &wallet_address_lower)
            .await?
            .ok_or_else(|| AuthMethodsError::Other("Wallet credential not found".to_string()))?;

        // Verify ownership
        if credential.identity_id != identity_id {
            return Err(AuthMethodsError::Other("Wallet does not belong to this identity".to_string()));
        }

        // Mark as revoked
        credential.revoked = true;
        credential.revoked_at = Some(Self::current_timestamp());

        // Update credential
        self.storage
            .put(CF_WALLET_CREDENTIALS, &wallet_address_lower, &credential)
            .await?;

        info!("Wallet credential revoked for identity {}", identity_id);

        Ok(())
    }

    async fn list_credentials(&self, identity_id: Uuid) -> Result<Vec<crate::traits::CredentialInfo>> {
        info!("Listing credentials for identity {}", identity_id);

        let mut credentials = Vec::new();

        // List email credentials
        // Note: We need to scan through all email credentials to find ones for this identity
        // In production, we'd want an index CF_AUTH_CREDENTIALS_BY_IDENTITY
        // For now, we'll check if there's an email credential (simplified)

        // List OAuth links
        for provider in [OAuthProvider::Google, OAuthProvider::X, OAuthProvider::EpicGames] {
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

        // List wallet credentials
        // Note: Similar issue - we'd want CF_WALLET_CREDENTIALS_BY_IDENTITY to be scannable
        // For now, this is a simplified implementation

        info!("Found {} credentials for identity {}", credentials.len(), identity_id);

        Ok(credentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_auth_storage::RocksDbStorage;

    #[test]
    fn test_derive_mfa_kek() {
        let identity_id1 = Uuid::new_v4();
        let identity_id2 = Uuid::new_v4();

        let storage = Arc::new(RocksDbStorage::open_test().unwrap());
        let policy = Arc::new(zero_auth_policy::PolicyEngineImpl::new());
        let identity_core = Arc::new(zero_auth_identity_core::IdentityCoreService::new(
            policy.clone(),
            Arc::new(MockEventPublisher),
            storage.clone(),
        ));

        let service = AuthMethodsService::new(identity_core.clone(), policy, storage);

        let kek1 = service.derive_mfa_kek(identity_id1);
        let kek2 = service.derive_mfa_kek(identity_id2);
        let kek1_again = service.derive_mfa_kek(identity_id1);

        // Same identity should produce same KEK
        assert_eq!(kek1, kek1_again);

        // Different identities should produce different KEKs
        assert_ne!(kek1, kek2);
    }

    // Mock event publisher for tests
    struct MockEventPublisher;

    #[async_trait]
    impl zero_auth_identity_core::EventPublisher for MockEventPublisher {
        async fn publish(
            &self,
            _event: zero_auth_identity_core::RevocationEvent,
        ) -> zero_auth_identity_core::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_oauth_initiate() {
        let storage = Arc::new(RocksDbStorage::open_test().unwrap());
        let policy = Arc::new(zero_auth_policy::PolicyEngineImpl::new());
        let identity_core = Arc::new(zero_auth_identity_core::IdentityCoreService::new(
            policy.clone(),
            Arc::new(MockEventPublisher),
            storage.clone(),
        ));

        let service = AuthMethodsService::new(identity_core.clone(), policy, storage.clone());

        // Create test identity
        let identity_id = Uuid::new_v4();
        let neural_key = zero_auth_crypto::NeuralKey::generate().unwrap();
        let identity = zero_auth_identity_core::Identity {
            identity_id,
            central_public_key: *neural_key.as_bytes(),
            status: zero_auth_identity_core::IdentityStatus::Active,
            created_at: 1000,
            updated_at: 1000,
            frozen_at: None,
            frozen_reason: None,
        };
        storage.put("identities", &identity_id, &identity).await.unwrap();

        // Initiate OAuth flow
        let result = service.oauth_initiate(identity_id, OAuthProvider::Google).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.auth_url.contains("client_id"));
        assert!(response.auth_url.contains("nonce"));
        assert!(!response.state.is_empty());

        // Verify state was stored
        let stored_state: Option<OAuthState> = storage
            .get(CF_OAUTH_STATES, &response.state)
            .await
            .unwrap();
        assert!(stored_state.is_some());
        let state = stored_state.unwrap();
        assert_eq!(state.identity_id, Some(identity_id));
        assert_eq!(state.provider, OAuthProvider::Google);
        assert!(!state.used);
    }

    #[tokio::test]
    async fn test_wallet_credential_attachment() {
        let storage = Arc::new(RocksDbStorage::open_test().unwrap());
        let policy = Arc::new(zero_auth_policy::PolicyEngineImpl::new());
        let identity_core = Arc::new(zero_auth_identity_core::IdentityCoreService::new(
            policy.clone(),
            Arc::new(MockEventPublisher),
            storage.clone(),
        ));

        let service = AuthMethodsService::new(identity_core.clone(), policy, storage.clone());

        // Create test identity
        let identity_id = Uuid::new_v4();
        let neural_key = zero_auth_crypto::NeuralKey::generate().unwrap();
        let identity = zero_auth_identity_core::Identity {
            identity_id,
            central_public_key: *neural_key.as_bytes(),
            status: zero_auth_identity_core::IdentityStatus::Active,
            created_at: 1000,
            updated_at: 1000,
            frozen_at: None,
            frozen_reason: None,
        };
        storage.put("identities", &identity_id, &identity).await.unwrap();

        // Attach wallet credential
        let wallet_address = "0x1234567890abcdef1234567890abcdef12345678";
        let result = service
            .attach_wallet_credential(identity_id, wallet_address.to_string(), "ethereum".to_string())
            .await;
        assert!(result.is_ok());

        // Verify credential was stored
        let stored_cred: Option<WalletCredential> = storage
            .get(CF_WALLET_CREDENTIALS, &wallet_address.to_lowercase())
            .await
            .unwrap();
        assert!(stored_cred.is_some());
        let cred = stored_cred.unwrap();
        assert_eq!(cred.identity_id, identity_id);
        assert_eq!(cred.chain, "ethereum");
        assert!(!cred.revoked);

        // Try to attach same wallet again (should fail)
        let result2 = service
            .attach_wallet_credential(identity_id, wallet_address.to_string(), "ethereum".to_string())
            .await;
        assert!(result2.is_err());
    }

    #[tokio::test]
    async fn test_wallet_credential_revocation() {
        let storage = Arc::new(RocksDbStorage::open_test().unwrap());
        let policy = Arc::new(zero_auth_policy::PolicyEngineImpl::new());
        let identity_core = Arc::new(zero_auth_identity_core::IdentityCoreService::new(
            policy.clone(),
            Arc::new(MockEventPublisher),
            storage.clone(),
        ));

        let service = AuthMethodsService::new(identity_core.clone(), policy, storage.clone());

        // Create test identity
        let identity_id = Uuid::new_v4();
        let neural_key = zero_auth_crypto::NeuralKey::generate().unwrap();
        let identity = zero_auth_identity_core::Identity {
            identity_id,
            central_public_key: *neural_key.as_bytes(),
            status: zero_auth_identity_core::IdentityStatus::Active,
            created_at: 1000,
            updated_at: 1000,
            frozen_at: None,
            frozen_reason: None,
        };
        storage.put("identities", &identity_id, &identity).await.unwrap();

        // Attach wallet credential
        let wallet_address = "0x1234567890abcdef1234567890abcdef12345678";
        service
            .attach_wallet_credential(identity_id, wallet_address.to_string(), "ethereum".to_string())
            .await
            .unwrap();

        // Revoke credential
        let result = service
            .revoke_wallet_credential(identity_id, wallet_address.to_string())
            .await;
        assert!(result.is_ok());

        // Verify credential is revoked
        let stored_cred: Option<WalletCredential> = storage
            .get(CF_WALLET_CREDENTIALS, &wallet_address.to_lowercase())
            .await
            .unwrap();
        assert!(stored_cred.is_some());
        let cred = stored_cred.unwrap();
        assert!(cred.revoked);
        assert!(cred.revoked_at.is_some());
    }

    #[tokio::test]
    async fn test_list_credentials() {
        let storage = Arc::new(RocksDbStorage::open_test().unwrap());
        let policy = Arc::new(zero_auth_policy::PolicyEngineImpl::new());
        let identity_core = Arc::new(zero_auth_identity_core::IdentityCoreService::new(
            policy.clone(),
            Arc::new(MockEventPublisher),
            storage.clone(),
        ));

        let service = AuthMethodsService::new(identity_core.clone(), policy, storage.clone());

        // Create test identity
        let identity_id = Uuid::new_v4();
        let neural_key = zero_auth_crypto::NeuralKey::generate().unwrap();
        let identity = zero_auth_identity_core::Identity {
            identity_id,
            central_public_key: *neural_key.as_bytes(),
            status: zero_auth_identity_core::IdentityStatus::Active,
            created_at: 1000,
            updated_at: 1000,
            frozen_at: None,
            frozen_reason: None,
        };
        storage.put("identities", &identity_id, &identity).await.unwrap();

        // Initially no credentials
        let creds = service.list_credentials(identity_id).await.unwrap();
        assert_eq!(creds.len(), 0);

        // Add OAuth link manually for testing
        let link = OAuthLink {
            link_id: Uuid::new_v4(),
            identity_id,
            provider: OAuthProvider::Google,
            provider_user_id: "google_user_123".to_string(),
            provider_email: Some("test@example.com".to_string()),
            email_verified: Some(true),
            display_name: Some("Test User".to_string()),
            linked_at: 1000,
            last_auth_at: 1000,
            revoked: false,
            revoked_at: None,
        };
        let link_key = format!("{}:{}", OAuthProvider::Google.as_str(), link.link_id);
        storage.put(CF_OAUTH_LINKS, &link_key, &link).await.unwrap();
        let identity_index_key = format!("{}:{}", identity_id, OAuthProvider::Google.as_str());
        storage
            .put(CF_OAUTH_LINKS_BY_IDENTITY, &identity_index_key, &link.link_id)
            .await
            .unwrap();

        // Now should have 1 credential
        let creds = service.list_credentials(identity_id).await.unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].credential_type, crate::traits::CredentialType::OAuth);
        assert!(!creds[0].revoked);
    }
}
