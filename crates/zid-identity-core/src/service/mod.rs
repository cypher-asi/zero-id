//! Identity Core service implementation.

mod ceremonies;
mod identity;
mod machine;
mod managed;
mod namespace;
mod upgrade;

// Re-export managed identity types
pub use managed::{CreateManagedIdentityRequest, CreateManagedIdentityResponse};

// Re-export upgrade ceremony types
pub use upgrade::{TierStatusResponse, UpgradeIdentityRequest, UpgradeIdentityResponse};

use crate::{errors::*, traits::*, types::*};
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;
use zid_policy::PolicyEngine;
use zid_storage::{Storage, CF_MACHINE_KEYS, CF_MACHINE_KEYS_BY_IDENTITY};

/// Identity Core service implementation
pub struct IdentityCoreService<P, E, S>
where
    P: PolicyEngine,
    E: EventPublisher,
    S: Storage,
{
    pub(super) policy: Arc<P>,
    pub(super) event_publisher: Arc<E>,
    pub(super) storage: Arc<S>,
}

impl<P, E, S> IdentityCoreService<P, E, S>
where
    P: PolicyEngine,
    E: EventPublisher,
    S: Storage,
{
    /// Create a new Identity Core service
    pub fn new(policy: Arc<P>, event_publisher: Arc<E>, storage: Arc<S>) -> Self {
        Self {
            policy,
            event_publisher,
            storage,
        }
    }

    /// List active machines for an identity
    pub(super) async fn list_active_machines(&self, identity_id: Uuid) -> Result<Vec<MachineKey>> {
        let prefix = identity_id;
        let machines_index: Vec<(Vec<u8>, ())> = self
            .storage
            .get_by_prefix(CF_MACHINE_KEYS_BY_IDENTITY, &prefix)
            .await?;

        let mut active_machines = Vec::new();

        for (key_bytes, _) in machines_index {
            // Key format with bincode serialization:
            // - 8 bytes: length prefix for first Uuid (always 16)
            // - 16 bytes: identity_id
            // - 8 bytes: length prefix for second Uuid (always 16)
            // - 16 bytes: machine_id
            // Total: 48 bytes
            if key_bytes.len() >= 48 {
                let machine_id_bytes = &key_bytes[32..48];
                let machine_id = Uuid::from_slice(machine_id_bytes).map_err(|e| {
                    IdentityCoreError::Storage(zid_storage::StorageError::Deserialization(
                        e.to_string(),
                    ))
                })?;

                if let Some(machine) = self.storage.get(CF_MACHINE_KEYS, &machine_id).await? {
                    let machine: MachineKey = machine;
                    if !machine.revoked {
                        active_machines.push(machine);
                    }
                }
            }
        }

        Ok(active_machines)
    }

    /// Generate next event sequence number for a namespace
    pub(super) async fn next_event_sequence(&self, _namespace_id: Uuid) -> Result<u64> {
        Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| IdentityCoreError::Other(format!("Time error: {}", e)))?
            .as_nanos() as u64)
    }

    /// Verify approval signatures for a ceremony
    pub(super) fn verify_approval_signatures(
        &self,
        message: &[u8],
        approvals: &[Approval],
        active_machines: &[MachineKey],
    ) -> Result<()> {
        use zid_crypto::verify_signature;

        for approval in approvals {
            let machine = active_machines
                .iter()
                .find(|m| m.machine_id == approval.machine_id)
                .ok_or(IdentityCoreError::InvalidApprovingMachine)?;

            verify_signature(
                &machine.signing_public_key,
                message,
                &approval
                    .signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| IdentityCoreError::InvalidApprovalSignature)?,
            )?;

            const APPROVAL_EXPIRY_SECONDS: u64 = 900;
            let current_time = current_timestamp();
            if current_time > approval.timestamp + APPROVAL_EXPIRY_SECONDS {
                return Err(IdentityCoreError::ApprovalExpired);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<P, E, S> IdentityCore for IdentityCoreService<P, E, S>
where
    P: PolicyEngine + 'static,
    E: EventPublisher + 'static,
    S: Storage + 'static,
{
    async fn create_identity(&self, request: CreateIdentityRequest) -> Result<Identity> {
        self.create_identity_internal(request).await
    }

    async fn create_managed_identity(
        &self,
        params: crate::traits::CreateManagedIdentityParams,
    ) -> Result<crate::traits::CreateManagedIdentityResult> {
        let request = CreateManagedIdentityRequest {
            service_master_key: params.service_master_key,
            method_type: params.method_type,
            method_id: params.method_id,
            namespace_name: params.namespace_name,
        };
        let response = self.create_managed_identity(request).await?;
        Ok(crate::traits::CreateManagedIdentityResult {
            identity: response.identity,
            machine_id: response.machine_id,
            namespace_id: response.namespace_id,
        })
    }

    async fn get_identity(&self, identity_id: Uuid) -> Result<Identity> {
        self.get_identity_internal(identity_id).await
    }

    async fn disable_identity(&self, identity_id: Uuid) -> Result<()> {
        self.disable_identity_internal(identity_id).await
    }

    async fn enable_identity(&self, identity_id: Uuid) -> Result<()> {
        self.enable_identity_internal(identity_id).await
    }

    async fn freeze_identity(
        &self,
        identity_id: Uuid,
        reason: FreezeReason,
        approvals: Vec<Approval>,
    ) -> Result<()> {
        self.freeze_identity_internal(identity_id, reason, approvals)
            .await
    }

    async fn unfreeze_identity(&self, identity_id: Uuid, approvals: Vec<Approval>) -> Result<()> {
        self.unfreeze_identity_internal(identity_id, approvals)
            .await
    }

    async fn enroll_machine_key(
        &self,
        identity_id: Uuid,
        machine_key: MachineKey,
        authorization_signature: Vec<u8>,
        mfa_verified: bool,
        ip_address: String,
        user_agent: String,
    ) -> Result<Uuid> {
        self.enroll_machine_key_internal(
            identity_id,
            machine_key,
            authorization_signature,
            mfa_verified,
            ip_address,
            user_agent,
        )
        .await
    }

    async fn get_machine_key(&self, machine_id: Uuid) -> Result<MachineKey> {
        self.get_machine_key_internal(machine_id).await
    }

    async fn list_machines(
        &self,
        identity_id: Uuid,
        namespace_id: Uuid,
    ) -> Result<Vec<MachineKey>> {
        self.list_machines_internal(identity_id, namespace_id).await
    }

    async fn revoke_machine_key(
        &self,
        machine_id: Uuid,
        revoked_by: Uuid,
        reason: String,
        mfa_verified: bool,
        ip_address: String,
        user_agent: String,
    ) -> Result<()> {
        self.revoke_machine_key_internal(
            machine_id,
            revoked_by,
            reason,
            mfa_verified,
            ip_address,
            user_agent,
        )
        .await
    }

    async fn rotate_neural_key(&self, request: RotationRequest) -> Result<()> {
        self.rotate_neural_key_internal(request).await
    }

    async fn initiate_recovery(
        &self,
        identity_id: Uuid,
        recovery_machine_key: MachineKey,
        approvals: Vec<Approval>,
    ) -> Result<Uuid> {
        self.initiate_recovery_internal(identity_id, recovery_machine_key, approvals)
            .await
    }

    async fn create_namespace(
        &self,
        namespace_id: Uuid,
        name: String,
        owner_identity_id: Uuid,
    ) -> Result<Namespace> {
        self.create_namespace_internal(namespace_id, name, owner_identity_id)
            .await
    }

    async fn get_namespace(&self, namespace_id: Uuid) -> Result<Namespace> {
        self.get_namespace_internal(namespace_id).await
    }

    async fn get_namespace_membership(
        &self,
        identity_id: Uuid,
        namespace_id: Uuid,
    ) -> Result<Option<IdentityNamespaceMembership>> {
        self.get_namespace_membership_internal(identity_id, namespace_id)
            .await
    }

    // ========================================================================
    // Namespace Management
    // ========================================================================

    async fn list_namespaces(&self, identity_id: Uuid) -> Result<Vec<Namespace>> {
        self.list_namespaces_internal(identity_id).await
    }

    async fn update_namespace(
        &self,
        namespace_id: Uuid,
        name: String,
        requester_id: Uuid,
    ) -> Result<Namespace> {
        self.update_namespace_internal(namespace_id, name, requester_id)
            .await
    }

    async fn deactivate_namespace(&self, namespace_id: Uuid, requester_id: Uuid) -> Result<()> {
        self.deactivate_namespace_internal(namespace_id, requester_id)
            .await
    }

    async fn reactivate_namespace(&self, namespace_id: Uuid, requester_id: Uuid) -> Result<()> {
        self.reactivate_namespace_internal(namespace_id, requester_id)
            .await
    }

    async fn delete_namespace(&self, namespace_id: Uuid, requester_id: Uuid) -> Result<()> {
        self.delete_namespace_internal(namespace_id, requester_id)
            .await
    }

    // ========================================================================
    // Namespace Membership Management
    // ========================================================================

    async fn list_namespace_members(
        &self,
        namespace_id: Uuid,
        requester_id: Uuid,
    ) -> Result<Vec<IdentityNamespaceMembership>> {
        self.list_namespace_members_internal(namespace_id, requester_id)
            .await
    }

    async fn add_namespace_member(
        &self,
        namespace_id: Uuid,
        identity_id: Uuid,
        role: NamespaceRole,
        requester_id: Uuid,
    ) -> Result<IdentityNamespaceMembership> {
        self.add_namespace_member_internal(namespace_id, identity_id, role, requester_id)
            .await
    }

    async fn update_namespace_member(
        &self,
        namespace_id: Uuid,
        identity_id: Uuid,
        role: NamespaceRole,
        requester_id: Uuid,
    ) -> Result<IdentityNamespaceMembership> {
        self.update_namespace_member_internal(namespace_id, identity_id, role, requester_id)
            .await
    }

    async fn remove_namespace_member(
        &self,
        namespace_id: Uuid,
        identity_id: Uuid,
        requester_id: Uuid,
    ) -> Result<()> {
        self.remove_namespace_member_internal(namespace_id, identity_id, requester_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::mocks::MockEventPublisher;
    use zid_crypto::{
        canonicalize_identity_creation_message, derive_identity_signing_keypair, sign_message,
        MachineKeyCapabilities, NeuralKey,
    };
    use zid_policy::PolicyEngineImpl;
    use zid_storage::RocksDbStorage;

    #[tokio::test]
    async fn test_create_identity() {
        let storage: Arc<RocksDbStorage> = Arc::new(RocksDbStorage::open_test().unwrap());
        let policy = Arc::new(PolicyEngineImpl::new(Arc::clone(&storage)));
        let events = Arc::new(MockEventPublisher);
        let service = IdentityCoreService::new(policy, events, storage);

        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = Uuid::new_v4();
        let (identity_signing_public_key, identity_keypair) =
            derive_identity_signing_keypair(&neural_key, &identity_id).unwrap();

        let machine_id = Uuid::new_v4();
        let machine_key = MachineKey {
            machine_id,
            identity_id,
            namespace_id: identity_id,
            signing_public_key: [1u8; 32],
            encryption_public_key: [2u8; 32],
            capabilities: MachineKeyCapabilities::FULL_DEVICE,
            epoch: 0,
            created_at: current_timestamp(),
            expires_at: None,
            last_used_at: None,
            device_name: "test-device".to_string(),
            device_platform: "test".to_string(),
            revoked: false,
            revoked_at: None,
            key_scheme: Default::default(),
            pq_signing_public_key: None,
            pq_encryption_public_key: None,
        };

        let message = canonicalize_identity_creation_message(
            &identity_id,
            &identity_signing_public_key,
            &machine_id,
            &machine_key.signing_public_key,
            &machine_key.encryption_public_key,
            machine_key.created_at,
        );

        let signature = sign_message(&identity_keypair, &message);

        let request = CreateIdentityRequest {
            identity_id,
            identity_signing_public_key,
            machine_key,
            authorization_signature: signature.to_vec(),
            namespace_name: Some("test-namespace".to_string()),
            created_at: current_timestamp(),
        };

        let identity = service.create_identity(request).await.unwrap();
        assert_eq!(identity.identity_id, identity_id);
        assert_eq!(identity.status, IdentityStatus::Active);
    }
}
