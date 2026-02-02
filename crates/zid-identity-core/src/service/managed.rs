//! Managed identity creation service.
//!
//! This module handles the creation of managed identities - identities where the
//! Identity Signing Key (ISK) is derived from the service master key rather than
//! a client-generated Neural Key.
//!
//! Managed identities can be created via:
//! - Email + password
//! - OAuth providers (Google, X, Epic Games)
//! - Wallet signatures (Ethereum, Solana)
//!
//! Managed identities have limited capabilities and should be upgraded to
//! self-sovereign identities for full functionality.

use crate::{errors::*, traits::EventPublisher, types::*};
use tracing::info;
use uuid::Uuid;
use zid_crypto::{current_timestamp, derive_managed_identity_signing_keypair, MachineKeyCapabilities};
use zid_policy::PolicyEngine;
use zid_storage::{
    traits::BatchExt, Storage, CF_IDENTITIES, CF_IDENTITY_NAMESPACE_MEMBERSHIPS, CF_MACHINE_KEYS,
    CF_MACHINE_KEYS_BY_IDENTITY, CF_NAMESPACES, CF_NAMESPACES_BY_IDENTITY,
};

use super::IdentityCoreService;

/// Request to create a managed identity
#[derive(Debug, Clone)]
pub struct CreateManagedIdentityRequest {
    /// Service master key (used to derive ISK)
    pub service_master_key: [u8; 32],
    /// Authentication method type (e.g., "oauth:google", "email", "wallet:evm")
    pub method_type: String,
    /// Method-specific identifier (e.g., provider sub, email hash, wallet address)
    pub method_id: String,
    /// Optional namespace name for the personal namespace
    pub namespace_name: Option<String>,
}

/// Response from managed identity creation
#[derive(Debug, Clone)]
pub struct CreateManagedIdentityResponse {
    /// Created identity
    pub identity: Identity,
    /// Virtual machine ID for this identity
    pub machine_id: Uuid,
    /// Personal namespace ID (same as identity_id)
    pub namespace_id: Uuid,
}

impl<P, E, S> IdentityCoreService<P, E, S>
where
    P: PolicyEngine + 'static,
    E: EventPublisher + 'static,
    S: Storage + 'static,
{
    /// Create a managed identity with server-derived keys
    ///
    /// This creates an identity with:
    /// - Identity Signing Key derived from service master key + auth method
    /// - Tier set to Managed
    /// - No neural_key_commitment (only present for self-sovereign)
    /// - A virtual machine for authentication
    ///
    /// # Arguments
    ///
    /// * `request` - CreateManagedIdentityRequest containing method details
    ///
    /// # Returns
    ///
    /// CreateManagedIdentityResponse with identity, machine, and namespace info
    pub async fn create_managed_identity(
        &self,
        request: CreateManagedIdentityRequest,
    ) -> Result<CreateManagedIdentityResponse> {
        info!(
            "Creating managed identity for method: {}:{}",
            request.method_type,
            if request.method_id.len() > 20 {
                format!("{}...", &request.method_id[..20])
            } else {
                request.method_id.clone()
            }
        );

        // Generate deterministic identity_id from method type + id
        let identity_id = Self::derive_managed_identity_id(&request.method_type, &request.method_id);

        // Check if identity already exists
        if let Ok(existing) = self.get_identity_internal(identity_id).await {
            return Ok(CreateManagedIdentityResponse {
                identity: existing,
                machine_id: Self::derive_virtual_machine_id(identity_id),
                namespace_id: identity_id,
            });
        }

        // Derive ISK from service master key
        let (identity_signing_public_key, _keypair) = derive_managed_identity_signing_keypair(
            &request.service_master_key,
            &request.method_type,
            &request.method_id,
        )?;

        // Create the identity, namespace, and virtual machine
        let timestamp = current_timestamp();
        
        let identity = Identity {
            identity_id,
            identity_signing_public_key,
            status: IdentityStatus::Active,
            tier: IdentityTier::Managed,
            neural_key_commitment: None, // Only present for self-sovereign
            created_at: timestamp,
            updated_at: timestamp,
            frozen_at: None,
            frozen_reason: None,
        };

        let namespace = Namespace {
            namespace_id: identity_id,
            name: request
                .namespace_name
                .unwrap_or_else(|| format!("personal-{}", identity_id)),
            created_at: timestamp,
            owner_identity_id: identity_id,
            active: true,
        };

        let membership = IdentityNamespaceMembership {
            identity_id,
            namespace_id: identity_id,
            role: NamespaceRole::Owner,
            joined_at: timestamp,
        };

        // Create a virtual machine for this managed identity
        let machine_id = Self::derive_virtual_machine_id(identity_id);
        let virtual_machine = Self::build_virtual_machine_for_managed(
            identity_id,
            machine_id,
            &request.service_master_key,
            timestamp,
        )?;

        // Persist everything atomically
        self.persist_managed_identity_batch(&identity, &namespace, &membership, &virtual_machine)
            .await?;

        info!(
            "Managed identity created: {} (tier: {:?})",
            identity_id, identity.tier
        );

        Ok(CreateManagedIdentityResponse {
            identity,
            machine_id,
            namespace_id: identity_id,
        })
    }

    /// Derive a deterministic identity_id from auth method
    fn derive_managed_identity_id(method_type: &str, method_id: &str) -> Uuid {
        use zid_crypto::hkdf_derive_32;

        let mut ikm = Vec::with_capacity(method_type.len() + method_id.len());
        ikm.extend_from_slice(method_type.as_bytes());
        ikm.extend_from_slice(method_id.as_bytes());

        let hash = hkdf_derive_32(&ikm, b"cypher:managed:identity-id:v1")
            .expect("HKDF derivation should not fail");

        // Use first 16 bytes as UUID
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&hash[..16]);
        Uuid::from_bytes(uuid_bytes)
    }

    /// Derive a deterministic virtual machine ID for a managed identity
    fn derive_virtual_machine_id(identity_id: Uuid) -> Uuid {
        use zid_crypto::hkdf_derive_32;

        let hash = hkdf_derive_32(identity_id.as_bytes(), b"cypher:managed:virtual-machine-id:v1")
            .expect("HKDF derivation should not fail");

        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&hash[..16]);
        Uuid::from_bytes(uuid_bytes)
    }

    /// Build a virtual machine for managed identity authentication
    fn build_virtual_machine_for_managed(
        identity_id: Uuid,
        machine_id: Uuid,
        service_master_key: &[u8; 32],
        timestamp: u64,
    ) -> Result<MachineKey> {
        use zid_crypto::{hkdf_derive_32, Ed25519KeyPair, X25519KeyPair};

        // Derive signing key
        let mut ikm = Vec::with_capacity(48);
        ikm.extend_from_slice(service_master_key);
        ikm.extend_from_slice(identity_id.as_bytes());

        let signing_seed = hkdf_derive_32(&ikm, b"cypher:managed:vm-signing:v1")?;
        let signing_keypair = Ed25519KeyPair::from_seed(&signing_seed)?;

        let encryption_seed = hkdf_derive_32(&ikm, b"cypher:managed:vm-encryption:v1")?;
        let encryption_keypair = X25519KeyPair::from_seed(&encryption_seed)?;

        Ok(MachineKey {
            machine_id,
            identity_id,
            namespace_id: identity_id,
            signing_public_key: signing_keypair.public_key().to_bytes(),
            encryption_public_key: *encryption_keypair.public_key().as_bytes(),
            capabilities: MachineKeyCapabilities::AUTHENTICATE,
            epoch: 0,
            created_at: timestamp,
            expires_at: None, // Virtual machines for managed identities don't expire
            last_used_at: Some(timestamp),
            device_name: "Virtual Machine (Managed Identity)".to_string(),
            device_platform: "managed".to_string(),
            revoked: false,
            revoked_at: None,
            key_scheme: Default::default(),
            pq_signing_public_key: None,
            pq_encryption_public_key: None,
        })
    }

    /// Persist managed identity and related entities atomically
    async fn persist_managed_identity_batch(
        &self,
        identity: &Identity,
        namespace: &Namespace,
        membership: &IdentityNamespaceMembership,
        machine_key: &MachineKey,
    ) -> Result<()> {
        let mut batch = self.storage.batch();

        batch.put(CF_IDENTITIES, &identity.identity_id, identity)?;
        batch.put(CF_NAMESPACES, &namespace.namespace_id, namespace)?;

        let membership_key = (identity.identity_id, namespace.namespace_id);
        batch.put(
            CF_IDENTITY_NAMESPACE_MEMBERSHIPS,
            &membership_key,
            membership,
        )?;

        let ns_index_key = (identity.identity_id, namespace.namespace_id);
        batch.put(CF_NAMESPACES_BY_IDENTITY, &ns_index_key, &())?;

        batch.put(CF_MACHINE_KEYS, &machine_key.machine_id, machine_key)?;

        let index_key = (identity.identity_id, machine_key.machine_id);
        batch.put(CF_MACHINE_KEYS_BY_IDENTITY, &index_key, &())?;

        batch.commit().await?;
        Ok(())
    }

    /// Get identity tier
    pub async fn get_identity_tier(&self, identity_id: Uuid) -> Result<IdentityTier> {
        let identity = self.get_identity_internal(identity_id).await?;
        Ok(identity.tier)
    }

    /// Check if identity can perform ceremony operations
    ///
    /// Returns Ok(()) if allowed, Err with reason if not.
    pub fn check_ceremony_allowed(identity: &Identity, ceremony_type: &str) -> Result<()> {
        if identity.tier.is_managed() {
            return Err(IdentityCoreError::Other(format!(
                "Ceremony '{}' requires self-sovereign identity. Current tier: managed. \
                 Please upgrade your identity to perform this operation.",
                ceremony_type
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_managed_identity_id_is_deterministic() {
        let method_type = "oauth:google";
        let method_id = "google-user-123";

        let id1 = IdentityCoreService::<
            zid_policy::PolicyEngineImpl<zid_storage::RocksDbStorage>,
            crate::traits::mocks::MockEventPublisher,
            zid_storage::RocksDbStorage,
        >::derive_managed_identity_id(method_type, method_id);

        let id2 = IdentityCoreService::<
            zid_policy::PolicyEngineImpl<zid_storage::RocksDbStorage>,
            crate::traits::mocks::MockEventPublisher,
            zid_storage::RocksDbStorage,
        >::derive_managed_identity_id(method_type, method_id);

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_derive_managed_identity_id_different_methods() {
        let id1 = IdentityCoreService::<
            zid_policy::PolicyEngineImpl<zid_storage::RocksDbStorage>,
            crate::traits::mocks::MockEventPublisher,
            zid_storage::RocksDbStorage,
        >::derive_managed_identity_id("oauth:google", "user-123");

        let id2 = IdentityCoreService::<
            zid_policy::PolicyEngineImpl<zid_storage::RocksDbStorage>,
            crate::traits::mocks::MockEventPublisher,
            zid_storage::RocksDbStorage,
        >::derive_managed_identity_id("email", "user@test.com");

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_check_ceremony_allowed_managed() {
        let identity = Identity {
            identity_id: Uuid::new_v4(),
            identity_signing_public_key: [0u8; 32],
            status: IdentityStatus::Active,
            tier: IdentityTier::Managed,
            neural_key_commitment: None,
            created_at: 1000,
            updated_at: 1000,
            frozen_at: None,
            frozen_reason: None,
        };

        let result = IdentityCoreService::<
            zid_policy::PolicyEngineImpl<zid_storage::RocksDbStorage>,
            crate::traits::mocks::MockEventPublisher,
            zid_storage::RocksDbStorage,
        >::check_ceremony_allowed(&identity, "freeze");

        assert!(result.is_err());
    }

    #[test]
    fn test_check_ceremony_allowed_self_sovereign() {
        let identity = Identity {
            identity_id: Uuid::new_v4(),
            identity_signing_public_key: [0u8; 32],
            status: IdentityStatus::Active,
            tier: IdentityTier::SelfSovereign,
            neural_key_commitment: Some([1u8; 32]),
            created_at: 1000,
            updated_at: 1000,
            frozen_at: None,
            frozen_reason: None,
        };

        let result = IdentityCoreService::<
            zid_policy::PolicyEngineImpl<zid_storage::RocksDbStorage>,
            crate::traits::mocks::MockEventPublisher,
            zid_storage::RocksDbStorage,
        >::check_ceremony_allowed(&identity, "freeze");

        assert!(result.is_ok());
    }
}
