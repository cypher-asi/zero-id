//! Email/password authentication methods.

use crate::{
    errors::*,
    types::*,
    validation::{validate_email, validate_password},
};
use tracing::info;
use uuid::Uuid;
use zero_auth_crypto::{
    blake3_hash, current_timestamp, generate_salt, hash_password, verify_password,
};
use zero_auth_identity_core::{IdentityCore, IdentityStatus};
use zero_auth_policy::{Operation, PolicyContext, PolicyEngine, Verdict};
use zero_auth_storage::Storage;

use super::{AuthMethodsService, CF_AUTH_CREDENTIALS, CF_MFA_SECRETS};

impl<I, P, S> AuthMethodsService<I, P, S>
where
    I: IdentityCore,
    P: PolicyEngine,
    S: Storage,
{
    /// Authenticate using email and password.
    ///
    /// # Arguments
    ///
    /// * `request` - Email authentication request with email, password, and optional MFA code
    /// * `ip_address` - Client IP address for policy evaluation
    /// * `user_agent` - Client user agent for policy evaluation
    ///
    /// # Returns
    ///
    /// Authentication result with identity and machine information
    pub(super) async fn authenticate_email(
        &self,
        request: EmailAuthRequest,
        ip_address: String,
        user_agent: String,
    ) -> Result<AuthResult> {
        info!(
            "Authenticating with email hash: {}",
            email_hash_for_log(&request.email)
        );

        // Validate email format
        validate_email(&request.email)?;

        // Step 1: Get and verify credential
        let credential = self.verify_email_credential(&request).await?;

        // Step 2: Check identity and MFA
        let (identity, mfa_verified) = self.check_identity_and_mfa(&request, &credential).await?;

        // Step 3: Determine or create machine_id
        let (final_machine_id, warning) = self
            .resolve_machine_id(credential.identity_id, request.machine_id)
            .await?;

        // Step 4: Evaluate policy
        let auth_result = self
            .evaluate_email_auth_policy(
                credential.identity_id,
                identity.identity_id,
                final_machine_id,
                mfa_verified,
                ip_address,
                user_agent,
                warning,
            )
            .await?;

        info!(
            "Email authentication successful for identity {}",
            credential.identity_id
        );

        Ok(auth_result)
    }

    /// Attach an email/password credential to an identity.
    ///
    /// # Arguments
    ///
    /// * `identity_id` - The identity to attach the credential to
    /// * `email` - The email address
    /// * `password` - The password (will be hashed with Argon2id)
    ///
    /// # Returns
    ///
    /// `Ok(())` if successful, error otherwise
    pub(super) async fn attach_email_credential(
        &self,
        identity_id: Uuid,
        email: String,
        password: String,
    ) -> Result<()> {
        info!("Attaching email credential for identity {}", identity_id);

        // Validate email format
        validate_email(&email)?;

        // Validate password strength
        validate_password(&password)?;

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
            created_at: current_timestamp(),
            updated_at: current_timestamp(),
            email_verified: false,
            verification_token: None,
        };

        // Store credential
        self.storage
            .put(CF_AUTH_CREDENTIALS, &email_lower, &credential)
            .await?;

        info!("Email credential attached for identity {}", identity_id);

        Ok(())
    }

    /// Verify email credential with constant-time password check (helper for authenticate_email).
    async fn verify_email_credential(&self, request: &EmailAuthRequest) -> Result<EmailCredential> {
        // Get credential
        let email_lower = request.email.to_lowercase();
        let credential_opt: Option<EmailCredential> =
            self.storage.get(CF_AUTH_CREDENTIALS, &email_lower).await?;

        // SECURITY: Constant-time authentication to prevent timing attacks
        // We always perform password verification, even if the email doesn't exist
        let (password_valid, credential) = if let Some(cred) = credential_opt {
            // Email exists - verify actual password
            let valid = verify_password(request.password.as_bytes(), &cred.password_hash).is_ok();
            (valid, Some(cred))
        } else {
            // Email doesn't exist - perform dummy password verification
            let dummy_hash =
                "$argon2id$v=19$m=19456,t=2,p=1$aGVsbG93b3JsZA$0123456789abcdef0123456789abcdef";
            let _ = verify_password(request.password.as_bytes(), dummy_hash);
            (false, None)
        };

        // Check authentication result
        if !password_valid || credential.is_none() {
            // Record failed attempt if we have a credential (email exists)
            if let Some(ref cred) = credential {
                self.record_failed_attempt(cred.identity_id).await?;
            }
            // Return generic error (don't reveal if email exists)
            return Err(AuthMethodsError::InvalidCredentials);
        }

        Ok(credential.unwrap())
    }

    /// Check identity status and MFA requirement (helper for authenticate_email).
    async fn check_identity_and_mfa(
        &self,
        request: &EmailAuthRequest,
        credential: &EmailCredential,
    ) -> Result<(zero_auth_identity_core::Identity, bool)> {
        // Get identity
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
            .get::<Uuid, crate::MfaSecret>(CF_MFA_SECRETS, &credential.identity_id)
            .await?
        {
            if mfa_secret.enabled {
                let code = request
                    .mfa_code
                    .as_ref()
                    .ok_or(AuthMethodsError::MfaRequired)?;
                if !self
                    .verify_mfa(credential.identity_id, code.clone())
                    .await?
                {
                    return Err(AuthMethodsError::InvalidMfaCode);
                }
                true
            } else {
                false
            }
        } else {
            false
        };

        Ok((identity, mfa_verified))
    }

    /// Resolve machine ID - verify provided or create virtual (helper for authenticate_email).
    async fn resolve_machine_id(
        &self,
        identity_id: Uuid,
        machine_id: Option<Uuid>,
    ) -> Result<(Uuid, Option<String>)> {
        if let Some(mid) = machine_id {
            // Primary flow: Verify machine belongs to identity
            let machine = self
                .identity_core
                .get_machine_key(mid)
                .await
                .map_err(|_| AuthMethodsError::MachineNotFound(mid))?;

            if machine.identity_id != identity_id {
                return Err(AuthMethodsError::MachineNotOwned {
                    machine_id: mid,
                    identity_id,
                });
            }

            if machine.revoked {
                return Err(AuthMethodsError::MachineRevoked(mid));
            }

            Ok((mid, None))
        } else {
            // No machine_id provided - create or reuse virtual machine
            let virtual_machine_id = self.create_virtual_machine(identity_id).await?;

            info!(
                "Using virtual machine {} for email auth (identity {})",
                virtual_machine_id, identity_id
            );

            Ok((
                virtual_machine_id,
                Some("Consider enrolling a real device for enhanced security".to_string()),
            ))
        }
    }

    /// Evaluate policy for email authentication (helper for authenticate_email).
    #[allow(clippy::too_many_arguments)]
    async fn evaluate_email_auth_policy(
        &self,
        identity_id: Uuid,
        namespace_id: Uuid,
        machine_id: Uuid,
        mfa_verified: bool,
        ip_address: String,
        user_agent: String,
        warning: Option<String>,
    ) -> Result<AuthResult> {
        // Get reputation score
        let reputation_score = self.policy.get_reputation(identity_id).await.unwrap_or(50);

        let decision = self
            .policy
            .evaluate(PolicyContext {
                identity_id,
                machine_id: Some(machine_id),
                namespace_id,
                auth_method: zero_auth_policy::AuthMethod::EmailPassword,
                mfa_verified,
                operation: Operation::Login,
                resource: None,
                ip_address,
                user_agent,
                timestamp: current_timestamp(),
                reputation_score,
                recent_failed_attempts: 0,
            })
            .await?;

        if decision.verdict != Verdict::Allow {
            return Err(AuthMethodsError::PolicyDenied(decision.reason));
        }

        // Record successful attempt
        self.policy
            .record_attempt(identity_id, Operation::Login, true)
            .await?;

        Ok(AuthResult {
            identity_id,
            machine_id,
            namespace_id,
            mfa_verified,
            auth_method: AuthMethod::EmailPassword,
            warning,
        })
    }
}

fn email_hash_for_log(email: &str) -> String {
    let hash = blake3_hash(email.as_bytes());
    hex::encode(&hash[..8])
}
