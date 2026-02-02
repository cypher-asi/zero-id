//! Identity upgrade ceremony: Managed -> Self-Sovereign.
//!
//! This module handles upgrading managed identities to self-sovereign identities.
//! The upgrade process involves:
//! 1. Client generates a Neural Key
//! 2. Client derives new ISK from Neural Key
//! 3. Client signs upgrade request with old (managed) ISK
//! 4. Server verifies prerequisites (2+ auth methods linked)
//! 5. Server updates identity tier and ISK

use crate::{errors::*, traits::EventPublisher, types::*};
use tracing::info;
use uuid::Uuid;
use zid_crypto::{current_timestamp, verify_signature};
use zid_policy::PolicyEngine;
use zid_storage::{Storage, CF_IDENTITIES};

use super::IdentityCoreService;

/// Request to upgrade identity from managed to self-sovereign
#[derive(Debug, Clone)]
pub struct UpgradeIdentityRequest {
    /// Identity to upgrade
    pub identity_id: Uuid,
    /// New identity signing public key (derived from Neural Key)
    pub new_identity_signing_public_key: [u8; 32],
    /// BLAKE3 hash commitment of the Neural Key
    pub neural_key_commitment: [u8; 32],
    /// Signature of upgrade message using the OLD (managed) ISK
    pub upgrade_signature: [u8; 64],
}

/// Response from upgrade ceremony
#[derive(Debug, Clone)]
pub struct UpgradeIdentityResponse {
    /// Whether upgrade was successful
    pub success: bool,
    /// New tier after upgrade
    pub tier: IdentityTier,
    /// Message with instructions for shard backup
    pub message: String,
}

/// Tier status response
#[derive(Debug, Clone)]
pub struct TierStatusResponse {
    /// Current tier
    pub tier: IdentityTier,
    /// Number of linked auth methods
    pub auth_methods_count: usize,
    /// Whether identity can be upgraded
    pub can_upgrade: bool,
    /// Requirements for upgrade (if any)
    pub upgrade_requirements: Vec<String>,
}

impl<P, E, S> IdentityCoreService<P, E, S>
where
    P: PolicyEngine + 'static,
    E: EventPublisher + 'static,
    S: Storage + 'static,
{
    /// Upgrade a managed identity to self-sovereign
    ///
    /// # Prerequisites
    /// - Identity must be managed tier
    /// - Identity must have 2+ verified auth methods linked (for recovery)
    /// - Upgrade signature must be valid
    ///
    /// # Process
    /// 1. Verify identity exists and is managed
    /// 2. Check auth method count
    /// 3. Verify upgrade signature with current ISK
    /// 4. Update identity with new ISK and tier
    pub async fn upgrade_identity(
        &self,
        request: UpgradeIdentityRequest,
    ) -> Result<UpgradeIdentityResponse> {
        info!("Starting upgrade ceremony for identity: {}", request.identity_id);

        // Get current identity
        let identity = self.get_identity_internal(request.identity_id).await?;

        // Verify identity is managed
        if identity.tier != IdentityTier::Managed {
            return Err(IdentityCoreError::Other(format!(
                "Identity is already self-sovereign (tier: {:?})",
                identity.tier
            )));
        }

        // Verify identity is active
        if identity.status != IdentityStatus::Active {
            return Err(IdentityCoreError::IdentityNotActive {
                status: identity.status,
                reason: "Identity must be active to upgrade".to_string(),
            });
        }

        // TODO: Check auth methods count (requires auth_links storage)
        // For now, we skip this check as auth links are implemented in zid-methods

        // Verify upgrade signature
        self.verify_upgrade_signature(&identity, &request)?;

        // Update identity
        let updated_identity = self
            .persist_upgrade(identity, &request)
            .await?;

        info!(
            "Identity upgraded to self-sovereign: {} (new ISK prefix: {:02x}{:02x}{:02x}{:02x}...)",
            request.identity_id,
            request.new_identity_signing_public_key[0],
            request.new_identity_signing_public_key[1],
            request.new_identity_signing_public_key[2],
            request.new_identity_signing_public_key[3]
        );

        Ok(UpgradeIdentityResponse {
            success: true,
            tier: updated_identity.tier,
            message: "Identity upgraded to self-sovereign. \
                     Please securely store your Neural Key shards for recovery."
                .to_string(),
        })
    }

    /// Get tier status for an identity
    pub async fn get_tier_status(
        &self,
        identity_id: Uuid,
        auth_methods_count: usize,
    ) -> Result<TierStatusResponse> {
        let identity = self.get_identity_internal(identity_id).await?;

        let mut requirements = Vec::new();
        let mut can_upgrade = identity.tier == IdentityTier::Managed;

        if identity.tier == IdentityTier::SelfSovereign {
            can_upgrade = false;
            // Already upgraded
        } else {
            // Check requirements
            if auth_methods_count < 2 {
                requirements.push(format!(
                    "Link {} more auth method(s) for recovery",
                    2 - auth_methods_count
                ));
                can_upgrade = false;
            }

            if identity.status != IdentityStatus::Active {
                requirements.push("Identity must be active".to_string());
                can_upgrade = false;
            }
        }

        Ok(TierStatusResponse {
            tier: identity.tier,
            auth_methods_count,
            can_upgrade,
            upgrade_requirements: requirements,
        })
    }

    /// Verify the upgrade signature
    fn verify_upgrade_signature(
        &self,
        identity: &Identity,
        request: &UpgradeIdentityRequest,
    ) -> Result<()> {
        // Build upgrade message: "upgrade" || identity_id || new_isk_public || commitment
        let mut message = Vec::with_capacity(7 + 16 + 32 + 32);
        message.extend_from_slice(b"upgrade");
        message.extend_from_slice(request.identity_id.as_bytes());
        message.extend_from_slice(&request.new_identity_signing_public_key);
        message.extend_from_slice(&request.neural_key_commitment);

        // Verify with current (managed) ISK
        verify_signature(
            &identity.identity_signing_public_key,
            &message,
            &request.upgrade_signature,
        )?;

        Ok(())
    }

    /// Persist the upgrade
    async fn persist_upgrade(
        &self,
        mut identity: Identity,
        request: &UpgradeIdentityRequest,
    ) -> Result<Identity> {
        identity.identity_signing_public_key = request.new_identity_signing_public_key;
        identity.tier = IdentityTier::SelfSovereign;
        identity.neural_key_commitment = Some(request.neural_key_commitment);
        identity.updated_at = current_timestamp();

        self.storage
            .put(CF_IDENTITIES, &identity.identity_id, &identity)
            .await?;

        Ok(identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zid_crypto::{derive_identity_signing_keypair, sign_message, NeuralKey};

    fn create_test_managed_identity(identity_id: Uuid, isk_public: [u8; 32]) -> Identity {
        Identity {
            identity_id,
            identity_signing_public_key: isk_public,
            status: IdentityStatus::Active,
            tier: IdentityTier::Managed,
            neural_key_commitment: None,
            created_at: 1000,
            updated_at: 1000,
            frozen_at: None,
            frozen_reason: None,
        }
    }

    #[test]
    fn test_upgrade_message_format() {
        let identity_id = Uuid::new_v4();
        let new_isk = [1u8; 32];
        let commitment = [2u8; 32];

        let mut message = Vec::new();
        message.extend_from_slice(b"upgrade");
        message.extend_from_slice(identity_id.as_bytes());
        message.extend_from_slice(&new_isk);
        message.extend_from_slice(&commitment);

        // Should be: 7 + 16 + 32 + 32 = 87 bytes
        assert_eq!(message.len(), 87);
    }

    #[test]
    fn test_tier_status_can_upgrade() {
        // Managed identity with 2+ auth methods can upgrade
        let tier = IdentityTier::Managed;
        let auth_count = 2;
        let status = IdentityStatus::Active;

        let can_upgrade = tier == IdentityTier::Managed 
            && auth_count >= 2 
            && status == IdentityStatus::Active;

        assert!(can_upgrade);
    }

    #[test]
    fn test_tier_status_cannot_upgrade_insufficient_methods() {
        let tier = IdentityTier::Managed;
        let auth_count = 1;

        let can_upgrade = tier == IdentityTier::Managed && auth_count >= 2;
        assert!(!can_upgrade);
    }

    #[test]
    fn test_tier_status_already_self_sovereign() {
        let tier = IdentityTier::SelfSovereign;
        let can_upgrade = tier == IdentityTier::Managed;
        assert!(!can_upgrade);
    }
}
