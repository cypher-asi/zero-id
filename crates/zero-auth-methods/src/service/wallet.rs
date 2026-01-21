//! EVM wallet authentication methods.

use crate::{challenge::*, errors::*, types::*, wallet::verify_wallet_signature};
use tracing::{info, warn};
use uuid::Uuid;
use zero_auth_crypto::current_timestamp;
use zero_auth_identity_core::{IdentityCore, IdentityStatus};
use zero_auth_policy::{Operation, PolicyContext, PolicyEngine, Verdict};
use zero_auth_storage::Storage;

use super::{
    AuthMethodsService, CF_CHALLENGES, CF_USED_NONCES, CF_WALLET_CREDENTIALS,
    CF_WALLET_CREDENTIALS_BY_IDENTITY,
};

impl<I, P, S> AuthMethodsService<I, P, S>
where
    I: IdentityCore,
    P: PolicyEngine,
    S: Storage,
{
    /// Authenticate using an EVM wallet signature.
    ///
    /// # Arguments
    ///
    /// * `signature` - Wallet signature containing challenge ID, wallet address, and signature
    /// * `ip_address` - Client IP address for policy evaluation
    /// * `user_agent` - Client user agent for policy evaluation
    ///
    /// # Returns
    ///
    /// Authentication result with identity and machine information
    pub(super) async fn authenticate_wallet(
        &self,
        signature: WalletSignature,
        ip_address: String,
        user_agent: String,
    ) -> Result<AuthResult> {
        info!("Authenticating wallet {}", signature.wallet_address);

        // Step 1: Get and validate challenge
        let challenge = self
            .validate_and_consume_wallet_challenge(&signature)
            .await?;

        // Step 2: Verify wallet signature
        self.verify_wallet_signature_internal(&challenge, &signature)?;

        // Step 3: Get wallet credential
        let credential = self
            .get_wallet_credential(&signature.wallet_address)
            .await?;

        // Step 4: Check identity status and MFA
        let (identity, mfa_verified) = self
            .check_wallet_identity_and_mfa(credential.identity_id, signature.mfa_code)
            .await?;

        // Step 5: Create virtual machine
        let machine_id = self.create_virtual_machine(credential.identity_id).await?;

        // Step 6: Evaluate policy
        let auth_result = self
            .evaluate_wallet_auth_policy(
                credential.identity_id,
                identity.identity_id,
                machine_id,
                mfa_verified,
                ip_address,
                user_agent,
            )
            .await?;

        // Step 7: Update credential last_used_at
        self.update_wallet_credential_usage(&signature.wallet_address, &credential)
            .await?;

        info!(
            "Wallet authentication successful for identity {}",
            credential.identity_id
        );

        Ok(auth_result)
    }

    /// Attach a wallet credential to an identity.
    ///
    /// # Arguments
    ///
    /// * `identity_id` - The identity to attach the wallet to
    /// * `wallet_address` - The EVM wallet address
    /// * `chain` - The blockchain chain (e.g., "ethereum", "polygon")
    ///
    /// # Returns
    ///
    /// `Ok(())` if successful, error otherwise
    pub(super) async fn attach_wallet_credential(
        &self,
        identity_id: Uuid,
        wallet_address: String,
        chain: String,
    ) -> Result<()> {
        info!(
            "Attaching wallet credential {} for identity {}",
            wallet_address, identity_id
        );

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
            return Err(AuthMethodsError::Other(
                "Wallet already linked to an identity".to_string(),
            ));
        }

        // Create credential
        let credential = WalletCredential {
            identity_id,
            wallet_address: wallet_address_lower.clone(),
            chain,
            created_at: current_timestamp(),
            last_used_at: current_timestamp(),
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

    /// Revoke a wallet credential.
    ///
    /// # Arguments
    ///
    /// * `identity_id` - The identity that owns the wallet
    /// * `wallet_address` - The wallet address to revoke
    ///
    /// # Returns
    ///
    /// `Ok(())` if successful, error if wallet not found or not owned by identity
    pub(super) async fn revoke_wallet_credential(
        &self,
        identity_id: Uuid,
        wallet_address: String,
    ) -> Result<()> {
        info!(
            "Revoking wallet credential {} for identity {}",
            wallet_address, identity_id
        );

        let wallet_address_lower = wallet_address.to_lowercase();

        // Get credential
        let mut credential: WalletCredential = self
            .storage
            .get(CF_WALLET_CREDENTIALS, &wallet_address_lower)
            .await?
            .ok_or_else(|| AuthMethodsError::Other("Wallet credential not found".to_string()))?;

        // Verify ownership
        if credential.identity_id != identity_id {
            return Err(AuthMethodsError::Other(
                "Wallet does not belong to this identity".to_string(),
            ));
        }

        // Mark as revoked
        credential.revoked = true;
        credential.revoked_at = Some(current_timestamp());

        // Update credential
        self.storage
            .put(CF_WALLET_CREDENTIALS, &wallet_address_lower, &credential)
            .await?;

        info!("Wallet credential revoked for identity {}", identity_id);

        Ok(())
    }

    /// Validate and consume wallet challenge (helper for authenticate_wallet).
    async fn validate_and_consume_wallet_challenge(
        &self,
        signature: &WalletSignature,
    ) -> Result<Challenge> {
        // SECURITY: We get-then-delete to prevent race conditions in challenge reuse
        let challenge: Challenge = self
            .storage
            .get(CF_CHALLENGES, &signature.challenge_id)
            .await?
            .ok_or(AuthMethodsError::ChallengeNotFound(signature.challenge_id))?;

        if challenge.used {
            warn!("Challenge {} already used", signature.challenge_id);
            let _ = self
                .storage
                .delete(CF_CHALLENGES, &signature.challenge_id)
                .await;
            return Err(AuthMethodsError::ChallengeAlreadyUsed(
                signature.challenge_id,
            ));
        }

        if is_challenge_expired(&challenge) {
            warn!("Challenge {} expired", signature.challenge_id);
            let _ = self
                .storage
                .delete(CF_CHALLENGES, &signature.challenge_id)
                .await;
            return Err(AuthMethodsError::ChallengeExpired);
        }

        // SECURITY: Check if nonce has been used (additional replay protection)
        let nonce_key = hex::encode(challenge.nonce);
        if self.storage.exists(CF_USED_NONCES, &nonce_key).await? {
            warn!(
                "Challenge nonce {} already used (replay attack detected)",
                nonce_key
            );
            let _ = self
                .storage
                .delete(CF_CHALLENGES, &signature.challenge_id)
                .await;
            return Err(AuthMethodsError::ChallengeAlreadyUsed(
                signature.challenge_id,
            ));
        }

        // SECURITY FIX: Delete challenge immediately after retrieving it
        self.storage
            .delete(CF_CHALLENGES, &signature.challenge_id)
            .await?;

        // Store used nonce with expiry timestamp
        let nonce_expiry = challenge.exp + 60;
        self.storage
            .put(CF_USED_NONCES, &nonce_key, &nonce_expiry)
            .await?;

        Ok(challenge)
    }

    /// Verify wallet signature (helper for authenticate_wallet).
    fn verify_wallet_signature_internal(
        &self,
        challenge: &Challenge,
        signature: &WalletSignature,
    ) -> Result<()> {
        let sig_bytes: [u8; 65] = signature.signature.as_slice().try_into().map_err(|_| {
            AuthMethodsError::WalletSignatureInvalid("Invalid signature length".to_string())
        })?;

        verify_wallet_signature(challenge, &signature.wallet_address, &sig_bytes)?;

        Ok(())
    }

    /// Get wallet credential (helper for authenticate_wallet).
    async fn get_wallet_credential(&self, wallet_address: &str) -> Result<WalletCredential> {
        let wallet_address_lower = wallet_address.to_lowercase();
        let credential: WalletCredential = self
            .storage
            .get(CF_WALLET_CREDENTIALS, &wallet_address_lower)
            .await?
            .ok_or_else(|| {
                AuthMethodsError::Other("Wallet not linked to any identity".to_string())
            })?;

        if credential.revoked {
            return Err(AuthMethodsError::Other(
                "Wallet credential is revoked".to_string(),
            ));
        }

        Ok(credential)
    }

    /// Check identity status and MFA for wallet auth (helper for authenticate_wallet).
    async fn check_wallet_identity_and_mfa(
        &self,
        identity_id: Uuid,
        mfa_code: Option<String>,
    ) -> Result<(zero_auth_identity_core::Identity, bool)> {
        // Check identity frozen status
        let identity = self.identity_core.get_identity(identity_id).await?;
        if identity.status == IdentityStatus::Frozen {
            return Err(AuthMethodsError::IdentityFrozen {
                identity_id,
                reason: identity.frozen_reason,
            });
        }

        // Check MFA if provided
        let mfa_verified = if let Some(mfa_code) = mfa_code {
            self.verify_mfa(identity_id, mfa_code).await?
        } else {
            false
        };

        Ok((identity, mfa_verified))
    }

    /// Evaluate policy for wallet authentication (helper for authenticate_wallet).
    async fn evaluate_wallet_auth_policy(
        &self,
        identity_id: Uuid,
        namespace_id: Uuid,
        machine_id: Uuid,
        mfa_verified: bool,
        ip_address: String,
        user_agent: String,
    ) -> Result<AuthResult> {
        // Get reputation score
        let reputation_score = self.policy.get_reputation(identity_id).await.unwrap_or(50);

        let decision = self
            .policy
            .evaluate(PolicyContext {
                identity_id,
                machine_id: Some(machine_id),
                namespace_id,
                auth_method: zero_auth_policy::AuthMethod::EvmWallet,
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
            auth_method: AuthMethod::EvmWallet,
            warning: Some("Consider enrolling a real device for enhanced security".to_string()),
        })
    }

    /// Update wallet credential usage timestamp (helper for authenticate_wallet).
    async fn update_wallet_credential_usage(
        &self,
        wallet_address: &str,
        credential: &WalletCredential,
    ) -> Result<()> {
        let wallet_address_lower = wallet_address.to_lowercase();
        let mut updated_credential = credential.clone();
        updated_credential.last_used_at = current_timestamp();
        self.storage
            .put(
                CF_WALLET_CREDENTIALS,
                &wallet_address_lower,
                &updated_credential,
            )
            .await?;

        Ok(())
    }
}
