//! Machine key authentication methods.

use crate::{challenge::*, errors::*, types::*};
use tracing::{debug, info, warn};
use uuid::Uuid;
use zero_auth_crypto::{current_timestamp, verify_signature};
use zero_auth_identity_core::{IdentityCore, IdentityStatus};
use zero_auth_policy::{Operation, PolicyContext, PolicyEngine, Verdict};
use zero_auth_storage::Storage;

use super::{AuthMethodsService, CF_CHALLENGES, CF_USED_NONCES};

impl<I, P, S> AuthMethodsService<I, P, S>
where
    I: IdentityCore,
    P: PolicyEngine,
    S: Storage,
{
    /// Create a new challenge for machine authentication.
    ///
    /// # Arguments
    ///
    /// * `request` - Challenge request containing machine ID and optional purpose
    ///
    /// # Returns
    ///
    /// A new challenge that must be signed by the machine's private key
    pub(super) async fn create_challenge(&self, request: ChallengeRequest) -> Result<Challenge> {
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
        let identity = self.identity_core.get_identity(machine.identity_id).await?;

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

    /// Authenticate using a signed challenge response.
    ///
    /// # Arguments
    ///
    /// * `response` - Challenge response with signature
    /// * `ip_address` - Client IP address for policy evaluation
    /// * `user_agent` - Client user agent for policy evaluation
    ///
    /// # Returns
    ///
    /// Authentication result with identity and machine information
    pub(super) async fn authenticate_machine(
        &self,
        response: ChallengeResponse,
        ip_address: String,
        user_agent: String,
    ) -> Result<AuthResult> {
        info!(
            "Authenticating machine {} with challenge {}",
            response.machine_id, response.challenge_id
        );

        // Step 1: Get and validate challenge
        let challenge = self.validate_and_consume_challenge(&response).await?;

        // Step 2: Get machine key and verify it's active
        let machine = self.check_machine_active(response.machine_id).await?;

        // Step 3: Check identity frozen status
        let _identity = self.check_identity_not_frozen(machine.identity_id).await?;

        // Step 4: Verify signature
        self.verify_challenge_signature(&machine, &challenge, &response)?;

        // Step 5: Check MFA if provided
        let mfa_verified = if let Some(mfa_code) = response.mfa_code {
            self.verify_mfa(machine.identity_id, mfa_code).await?
        } else {
            false
        };

        // Step 6: Evaluate policy
        let reputation_score = self
            .policy
            .get_reputation(machine.identity_id)
            .await
            .unwrap_or(50); // Default to neutral if error

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
                ip_address,
                user_agent,
                timestamp: current_timestamp(),
                reputation_score,
                recent_failed_attempts: 0,
                // Entity states checked separately in auth flow
                identity_status: None,
                machine_revoked: None,
                machine_capabilities: None,
                namespace_active: None,
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

    /// Validate and consume a challenge (helper for authenticate_machine).
    async fn validate_and_consume_challenge(
        &self,
        response: &ChallengeResponse,
    ) -> Result<Challenge> {
        // SECURITY: We get-then-delete to prevent race conditions in challenge reuse
        let challenge: Challenge = self
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
            let _ = self
                .storage
                .delete(CF_CHALLENGES, &response.challenge_id)
                .await;
            return Err(AuthMethodsError::ChallengeAlreadyUsed(
                response.challenge_id,
            ));
        }

        // Check expiry
        if is_challenge_expired(&challenge) {
            warn!("Challenge {} expired", response.challenge_id);
            let _ = self
                .storage
                .delete(CF_CHALLENGES, &response.challenge_id)
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
                .delete(CF_CHALLENGES, &response.challenge_id)
                .await;
            return Err(AuthMethodsError::ChallengeAlreadyUsed(
                response.challenge_id,
            ));
        }

        // SECURITY FIX: Delete challenge immediately after retrieving it
        // This provides atomic "consume" semantics - second attempt will get NotFound
        self.storage
            .delete(CF_CHALLENGES, &response.challenge_id)
            .await?;

        // Store used nonce with expiry timestamp (for cleanup)
        let nonce_expiry = challenge.exp + 60;
        self.storage
            .put(CF_USED_NONCES, &nonce_key, &nonce_expiry)
            .await?;

        Ok(challenge)
    }

    /// Check that machine is active (helper for authenticate_machine).
    async fn check_machine_active(
        &self,
        machine_id: Uuid,
    ) -> Result<zero_auth_identity_core::MachineKey> {
        let machine = self
            .identity_core
            .get_machine_key(machine_id)
            .await
            .map_err(|_| AuthMethodsError::MachineNotFound(machine_id))?;

        if machine.revoked {
            return Err(AuthMethodsError::MachineRevoked(machine_id));
        }

        Ok(machine)
    }

    /// Check that identity is not frozen (helper for authenticate_machine).
    async fn check_identity_not_frozen(
        &self,
        identity_id: Uuid,
    ) -> Result<zero_auth_identity_core::Identity> {
        let identity = self.identity_core.get_identity(identity_id).await?;

        if identity.status == IdentityStatus::Frozen {
            return Err(AuthMethodsError::IdentityFrozen {
                identity_id: identity.identity_id,
                reason: identity.frozen_reason,
            });
        }

        Ok(identity)
    }

    /// Verify challenge signature (helper for authenticate_machine).
    fn verify_challenge_signature(
        &self,
        machine: &zero_auth_identity_core::MachineKey,
        challenge: &Challenge,
        response: &ChallengeResponse,
    ) -> Result<()> {
        let canonical_message = canonicalize_challenge(challenge);

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

        Ok(())
    }
}
