//! Multi-factor authentication (TOTP) methods.

use crate::{errors::*, mfa::*, types::*};
use tracing::{info, warn};
use uuid::Uuid;
use zero_auth_crypto::current_timestamp;
use zero_auth_identity_core::IdentityCore;
use zero_auth_policy::{Operation, PolicyEngine};
use zero_auth_storage::Storage;

use super::{AuthMethodsService, CF_MFA_SECRETS};

impl<I, P, S> AuthMethodsService<I, P, S>
where
    I: IdentityCore,
    P: PolicyEngine,
    S: Storage,
{
    /// Setup MFA for an identity.
    ///
    /// Generates a new TOTP secret and backup codes. The MFA is not enabled
    /// until the user verifies they can generate valid codes with `enable_mfa`.
    ///
    /// # Arguments
    ///
    /// * `identity_id` - The identity to set up MFA for
    ///
    /// # Returns
    ///
    /// MFA setup information including QR code URI, secret, and backup codes
    pub(super) async fn setup_mfa(&self, identity_id: Uuid) -> Result<MfaSetup> {
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
            created_at: current_timestamp(),
            enabled: false, // Not enabled until verified
        };

        self.storage
            .put(CF_MFA_SECRETS, &identity_id, &mfa_secret)
            .await?;

        info!("MFA setup completed for identity {}", identity_id);

        Ok(setup)
    }

    /// Enable MFA after verifying the user can generate valid codes.
    ///
    /// # Arguments
    ///
    /// * `identity_id` - The identity to enable MFA for
    /// * `verification_code` - A valid TOTP code to prove the user has the secret
    ///
    /// # Returns
    ///
    /// `Ok(())` if successful, error if the code is invalid or MFA is already enabled
    pub(super) async fn enable_mfa(
        &self,
        identity_id: Uuid,
        verification_code: String,
    ) -> Result<()> {
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
        let secret = decrypt_mfa_secret_data(
            &mfa_secret.encrypted_secret,
            &mfa_secret.nonce,
            &kek,
            &identity_id,
        )?;

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

    /// Disable MFA for an identity.
    ///
    /// # Arguments
    ///
    /// * `identity_id` - The identity to disable MFA for
    /// * `mfa_code` - A valid TOTP or backup code to authorize the operation
    ///
    /// # Returns
    ///
    /// `Ok(())` if successful, error if the code is invalid
    pub(super) async fn disable_mfa(&self, identity_id: Uuid, mfa_code: String) -> Result<()> {
        info!("Disabling MFA for identity {}", identity_id);

        // Verify MFA code before disabling
        if !self.verify_mfa(identity_id, mfa_code).await? {
            return Err(AuthMethodsError::InvalidMfaCode);
        }

        // Delete MFA secret
        self.storage.delete(CF_MFA_SECRETS, &identity_id).await?;

        info!("MFA disabled for identity {}", identity_id);

        Ok(())
    }

    /// Verify an MFA code (TOTP or backup code).
    ///
    /// # Arguments
    ///
    /// * `identity_id` - The identity to verify MFA for
    /// * `code` - The TOTP or backup code to verify
    ///
    /// # Returns
    ///
    /// `Ok(true)` if valid, `Ok(false)` if invalid, error if MFA is not enabled or rate limited
    pub(super) async fn verify_mfa(&self, identity_id: Uuid, code: String) -> Result<bool> {
        // SECURITY: Rate limit MFA verification attempts (especially backup codes)
        if self.policy.check_identity_rate_limit(identity_id).is_none() {
            warn!("MFA verification rate limited for identity {}", identity_id);
            let _ = self
                .policy
                .record_attempt(identity_id, Operation::Login, false)
                .await;
            return Err(AuthMethodsError::Other(
                "Too many MFA verification attempts. Please try again later.".to_string(),
            ));
        }

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
        let secret = decrypt_mfa_secret_data(
            &mfa_secret.encrypted_secret,
            &mfa_secret.nonce,
            &kek,
            &identity_id,
        )?;

        // Try TOTP verification first
        if verify_totp_code(&secret, &code)? {
            let _ = self
                .policy
                .record_attempt(identity_id, Operation::Login, true)
                .await;
            return Ok(true);
        }

        // Try backup codes
        let code_hash = hash_backup_code(&code);
        if mfa_secret.backup_codes.contains(&code_hash) {
            // Remove used backup code from storage
            let mut updated_secret = mfa_secret.clone();
            updated_secret
                .backup_codes
                .retain(|hash| hash != &code_hash);

            // Update storage with modified backup codes
            self.storage
                .put(CF_MFA_SECRETS, &identity_id, &updated_secret)
                .await?;

            info!("Backup code used and removed for identity: {}", identity_id);
            let _ = self
                .policy
                .record_attempt(identity_id, Operation::Login, true)
                .await;
            return Ok(true);
        }

        // Record failed attempt for rate limiting
        let _ = self
            .policy
            .record_attempt(identity_id, Operation::Login, false)
            .await;
        Ok(false)
    }
}
