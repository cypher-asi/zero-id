//! Identity Core service implementation.

use crate::{errors::*, traits::*, types::*};
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;
use zero_auth_crypto::{
    canonicalize_enrollment_message, canonicalize_identity_creation_message, verify_signature,
};
use zero_auth_policy::PolicyEngine;
use zero_auth_storage::{
    traits::BatchExt, Storage, CF_IDENTITIES, CF_IDENTITY_NAMESPACE_MEMBERSHIPS, CF_MACHINE_KEYS,
    CF_MACHINE_KEYS_BY_IDENTITY, CF_NAMESPACES,
};

/// Identity Core service implementation
pub struct IdentityCoreService<P, E, S>
where
    P: PolicyEngine,
    E: EventPublisher,
    S: Storage,
{
    #[allow(dead_code)] // TODO: Implement policy checks in all operations
    policy: Arc<P>,
    event_publisher: Arc<E>,
    storage: Arc<S>,
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
    async fn list_active_machines(&self, identity_id: Uuid) -> Result<Vec<MachineKey>> {
        // Get all machines for identity
        let prefix = identity_id;
        let machines_index: Vec<(Vec<u8>, ())> = self
            .storage
            .get_by_prefix(CF_MACHINE_KEYS_BY_IDENTITY, &prefix)
            .await?;

        let mut active_machines = Vec::new();

        for (key_bytes, _) in machines_index {
            // Deserialize the composite key to get machine_id
            if key_bytes.len() >= 32 {
                let machine_id_bytes = &key_bytes[16..32];
                let machine_id = Uuid::from_slice(machine_id_bytes)
                    .map_err(|e| IdentityCoreError::Storage(
                        zero_auth_storage::StorageError::Deserialization(e.to_string())
                    ))?;

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
    /// 
    /// This is a simple implementation using timestamp-based sequencing.
    /// For production, consider using a dedicated sequence counter in the database.
    async fn next_event_sequence(&self, _namespace_id: Uuid) -> Result<u64> {
        // Simple implementation: use nanoseconds since epoch as sequence
        // This ensures monotonic ordering across events
        Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| IdentityCoreError::Other(format!("Time error: {}", e)))?
            .as_nanos() as u64)
    }

    /// Verify approval signatures for a ceremony
    fn verify_approval_signatures(
        &self,
        message: &[u8],
        approvals: &[Approval],
        active_machines: &[MachineKey],
    ) -> Result<()> {
        for approval in approvals {
            // Find the approving machine
            let machine = active_machines
                .iter()
                .find(|m| m.machine_id == approval.machine_id)
                .ok_or(IdentityCoreError::InvalidApprovingMachine)?;

            // Verify the signature
            verify_signature(
                &machine.signing_public_key,
                message,
                &approval
                    .signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| IdentityCoreError::InvalidApprovalSignature)?,
            )?;

            // Check approval not expired (15 minutes)
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
        info!("Creating identity: {}", request.identity_id);

        // Verify authorization signature
        let message = canonicalize_identity_creation_message(
            &request.identity_id,
            &request.central_public_key,
            &request.machine_key.machine_id,
            &request.machine_key.signing_public_key,
            &request.machine_key.encryption_public_key,
            request.created_at,
        );

        verify_signature(
            &request.central_public_key,
            &message,
            &request.authorization_signature.as_slice().try_into()
                .map_err(|_| IdentityCoreError::InvalidAuthorizationSignature)?,
        )?;

        // Create identity
        let identity = Identity {
            identity_id: request.identity_id,
            central_public_key: request.central_public_key,
            status: IdentityStatus::Active,
            created_at: request.created_at,
            updated_at: request.created_at,
            frozen_at: None,
            frozen_reason: None,
        };

        // Create default personal namespace (namespace_id == identity_id)
        let namespace = Namespace {
            namespace_id: request.identity_id, // CRITICAL: personal namespace_id == identity_id
            name: request
                .namespace_name
                .unwrap_or_else(|| format!("personal-{}", request.identity_id)),
            created_at: request.created_at,
            owner_identity_id: request.identity_id,
            active: true,
        };

        // Create namespace membership
        let membership = IdentityNamespaceMembership {
            identity_id: request.identity_id,
            namespace_id: namespace.namespace_id,
            role: NamespaceRole::Owner,
            joined_at: request.created_at,
        };

        // Atomic batch write
        let mut batch = self.storage.batch();

        batch.put(CF_IDENTITIES, &identity.identity_id, &identity)?;
        batch.put(CF_NAMESPACES, &namespace.namespace_id, &namespace)?;

        let membership_key = (identity.identity_id, namespace.namespace_id);
        batch.put(
            CF_IDENTITY_NAMESPACE_MEMBERSHIPS,
            &membership_key,
            &membership,
        )?;

        batch.put(
            CF_MACHINE_KEYS,
            &request.machine_key.machine_id,
            &request.machine_key,
        )?;

        let index_key = (identity.identity_id, request.machine_key.machine_id);
        batch.put(CF_MACHINE_KEYS_BY_IDENTITY, &index_key, &())?;

        batch.commit().await?;

        info!("Identity created successfully: {}", identity.identity_id);
        Ok(identity)
    }

    async fn get_identity(&self, identity_id: Uuid) -> Result<Identity> {
        self.storage
            .get(CF_IDENTITIES, &identity_id)
            .await?
            .ok_or(IdentityCoreError::NotFound(identity_id))
    }

    async fn disable_identity(&self, identity_id: Uuid) -> Result<()> {
        let mut identity = self.get_identity(identity_id).await?;
        identity.status = IdentityStatus::Disabled;
        identity.updated_at = current_timestamp();

        self.storage
            .put(CF_IDENTITIES, &identity_id, &identity)
            .await?;

        info!("Identity disabled: {}", identity_id);
        Ok(())
    }

    async fn enable_identity(&self, identity_id: Uuid) -> Result<()> {
        let mut identity = self.get_identity(identity_id).await?;

        if identity.status != IdentityStatus::Disabled {
            return Err(IdentityCoreError::IdentityNotActive {
                status: identity.status,
                reason: "Only disabled identities can be re-enabled".to_string(),
            });
        }

        identity.status = IdentityStatus::Active;
        identity.updated_at = current_timestamp();

        self.storage
            .put(CF_IDENTITIES, &identity_id, &identity)
            .await?;

        info!("Identity re-enabled: {}", identity_id);
        Ok(())
    }

    async fn freeze_identity(&self, identity_id: Uuid, reason: FreezeReason) -> Result<()> {
        let mut identity = self.get_identity(identity_id).await?;
        identity.status = IdentityStatus::Frozen;
        identity.frozen_at = Some(current_timestamp());
        identity.frozen_reason = Some(reason.to_string());
        identity.updated_at = current_timestamp();

        self.storage
            .put(CF_IDENTITIES, &identity_id, &identity)
            .await?;

        // Publish freeze event
        let sequence = self.next_event_sequence(identity_id).await?;
        self.event_publisher
            .publish(RevocationEvent {
                event_id: Uuid::new_v4(),
                event_type: EventType::IdentityFrozen,
                namespace_id: identity_id, // Personal namespace
                identity_id,
                machine_id: None,
                session_id: None,
                sequence,
                timestamp: current_timestamp(),
                reason: reason.to_string(),
            })
            .await?;

        info!("Identity frozen: {}", identity_id);
        Ok(())
    }

    async fn unfreeze_identity(&self, identity_id: Uuid, approvals: Vec<Approval>) -> Result<()> {
        let identity = self.get_identity(identity_id).await?;

        if identity.status != IdentityStatus::Frozen {
            return Err(IdentityCoreError::NotFrozen(identity_id));
        }

        let active_machines = self.list_active_machines(identity_id).await?;

        // Require 2 machine approvals if available
        let required_approvals = if active_machines.len() >= 2 { 2 } else { 1 };

        if approvals.len() < required_approvals {
            return Err(IdentityCoreError::InsufficientApprovals {
                required: required_approvals,
                provided: approvals.len(),
            });
        }

        // Verify approvals with proper signature checking
        // Message format: "unfreeze" || identity_id || timestamp
        let mut message = Vec::with_capacity(8 + 16 + 8);
        message.extend_from_slice(b"unfreeze");
        message.extend_from_slice(identity_id.as_bytes());
        
        // Use the first approval's timestamp for the message (all approvals should use same timestamp)
        if let Some(first_approval) = approvals.first() {
            message.extend_from_slice(&first_approval.timestamp.to_be_bytes());
        }
        
        self.verify_approval_signatures(&message, &approvals, &active_machines)?;

        // Unfreeze
        let mut updated_identity = identity;
        updated_identity.status = IdentityStatus::Active;
        updated_identity.frozen_at = None;
        updated_identity.frozen_reason = None;
        updated_identity.updated_at = current_timestamp();

        self.storage
            .put(CF_IDENTITIES, &identity_id, &updated_identity)
            .await?;

        info!("Identity unfrozen: {}", identity_id);
        Ok(())
    }

    async fn enroll_machine_key(
        &self,
        identity_id: Uuid,
        machine_key: MachineKey,
        authorization_signature: Vec<u8>,
    ) -> Result<Uuid> {
        // Get identity and check status
        let identity = self.get_identity(identity_id).await?;

        if identity.status != IdentityStatus::Active {
            return Err(IdentityCoreError::IdentityNotActive {
                status: identity.status,
                reason: "Cannot enroll machines for non-active identity".to_string(),
            });
        }

        // Verify authorization signature
        let message = canonicalize_enrollment_message(
            &machine_key.machine_id,
            &machine_key.namespace_id,
            &machine_key.signing_public_key,
            &machine_key.encryption_public_key,
            machine_key.capabilities.bits(),
            machine_key.created_at,
        );

        verify_signature(
            &identity.central_public_key,
            &message,
            &authorization_signature.as_slice().try_into()
                .map_err(|_| IdentityCoreError::InvalidAuthorizationSignature)?,
        )?;

        // Check if machine already exists
        if self
            .storage
            .exists(CF_MACHINE_KEYS, &machine_key.machine_id)
            .await?
        {
            return Err(IdentityCoreError::MachineAlreadyExists(
                machine_key.machine_id,
            ));
        }

        // Store machine key atomically
        let mut batch = self.storage.batch();

        batch.put(CF_MACHINE_KEYS, &machine_key.machine_id, &machine_key)?;

        let index_key = (identity_id, machine_key.machine_id);
        batch.put(CF_MACHINE_KEYS_BY_IDENTITY, &index_key, &())?;

        batch.commit().await?;

        info!("Machine key enrolled: {}", machine_key.machine_id);
        Ok(machine_key.machine_id)
    }

    async fn get_machine_key(&self, machine_id: Uuid) -> Result<MachineKey> {
        self.storage
            .get(CF_MACHINE_KEYS, &machine_id)
            .await?
            .ok_or(IdentityCoreError::MachineNotFound(machine_id))
    }

    async fn list_machines(
        &self,
        identity_id: Uuid,
        namespace_id: Uuid,
    ) -> Result<Vec<MachineKey>> {
        let all_machines = self.list_active_machines(identity_id).await?;

        // Filter by namespace
        let machines: Vec<MachineKey> = all_machines
            .into_iter()
            .filter(|m| m.namespace_id == namespace_id)
            .collect();

        Ok(machines)
    }

    async fn revoke_machine_key(
        &self,
        machine_id: Uuid,
        _revoked_by: Uuid,
        reason: String,
    ) -> Result<()> {
        let mut machine = self.get_machine_key(machine_id).await?;

        if machine.revoked {
            return Err(IdentityCoreError::AlreadyRevoked(machine_id));
        }

        machine.revoked = true;
        machine.revoked_at = Some(current_timestamp());

        self.storage.put(CF_MACHINE_KEYS, &machine_id, &machine).await?;

        // Publish revocation event
        let sequence = self.next_event_sequence(machine.namespace_id).await?;
        self.event_publisher
            .publish(RevocationEvent {
                event_id: Uuid::new_v4(),
                event_type: EventType::MachineRevoked,
                namespace_id: machine.namespace_id,
                identity_id: machine.identity_id,
                machine_id: Some(machine_id),
                session_id: None,
                sequence,
                timestamp: current_timestamp(),
                reason: reason.clone(),
            })
            .await?;

        info!("Machine key revoked: {}, reason: {}", machine_id, reason);
        Ok(())
    }

    async fn rotate_neural_key(&self, request: RotationRequest) -> Result<()> {
        let identity = self.get_identity(request.identity_id).await?;

        // Require 2+ approvals
        if request.approvals.len() < 2 {
            return Err(IdentityCoreError::InsufficientApprovals {
                required: 2,
                provided: request.approvals.len(),
            });
        }

        let active_machines = self.list_active_machines(request.identity_id).await?;

        // Verify approvals with signature checking
        let mut approving_machines = HashSet::new();

        // Check for duplicate approving machines
        for approval in &request.approvals {
            if !approving_machines.insert(approval.machine_id) {
                return Err(IdentityCoreError::DuplicateApproval(approval.machine_id));
            }
        }

        // Create canonical message for rotation approval
        // Message format: "rotate" || identity_id || new_central_public_key || timestamp
        let mut message = Vec::with_capacity(6 + 16 + 32 + 8);
        message.extend_from_slice(b"rotate");
        message.extend_from_slice(request.identity_id.as_bytes());
        message.extend_from_slice(&request.new_central_public_key);
        
        if let Some(first_approval) = request.approvals.first() {
            message.extend_from_slice(&first_approval.timestamp.to_be_bytes());
        }

        self.verify_approval_signatures(&message, &request.approvals, &active_machines)?;

        // Atomic rotation
        let mut batch = self.storage.batch();

        // Update central public key
        let mut updated_identity = identity;
        updated_identity.central_public_key = request.new_central_public_key;
        updated_identity.updated_at = current_timestamp();
        batch.put(
            CF_IDENTITIES,
            &updated_identity.identity_id,
            &updated_identity,
        )?;

        // Revoke all old machines
        for machine in active_machines {
            let mut revoked_machine = machine;
            revoked_machine.revoked = true;
            revoked_machine.revoked_at = Some(current_timestamp());
            batch.put(CF_MACHINE_KEYS, &revoked_machine.machine_id, &revoked_machine)?;
        }

        // Enroll new machines
        for new_machine in request.new_machines {
            batch.put(CF_MACHINE_KEYS, &new_machine.machine_id, &new_machine)?;
            let index_key = (request.identity_id, new_machine.machine_id);
            batch.put(CF_MACHINE_KEYS_BY_IDENTITY, &index_key, &())?;
        }

        batch.commit().await?;

        info!("Neural key rotated for identity: {}", request.identity_id);
        Ok(())
    }

    async fn initiate_recovery(
        &self,
        identity_id: Uuid,
        recovery_machine_key: MachineKey,
        approvals: Vec<Approval>,
    ) -> Result<Uuid> {
        let _identity = self.get_identity(identity_id).await?;
        let active_machines = self.list_active_machines(identity_id).await?;

        let approval_required = !active_machines.is_empty();

        if approval_required && approvals.is_empty() {
            return Err(IdentityCoreError::InsufficientApprovals {
                required: 1,
                provided: 0,
            });
        }

        // Verify approvals with signature checking
        if approval_required {
            // Message format: "recovery" || identity_id || recovery_machine_id || timestamp
            let mut message = Vec::with_capacity(8 + 16 + 16 + 8);
            message.extend_from_slice(b"recovery");
            message.extend_from_slice(identity_id.as_bytes());
            message.extend_from_slice(recovery_machine_key.machine_id.as_bytes());
            
            if let Some(first_approval) = approvals.first() {
                message.extend_from_slice(&first_approval.timestamp.to_be_bytes());
            }

            self.verify_approval_signatures(&message, &approvals, &active_machines)?;
        }

        // Enroll recovery machine (simplified - no signature check here)
        let mut batch = self.storage.batch();

        batch.put(
            CF_MACHINE_KEYS,
            &recovery_machine_key.machine_id,
            &recovery_machine_key,
        )?;

        let index_key = (identity_id, recovery_machine_key.machine_id);
        batch.put(CF_MACHINE_KEYS_BY_IDENTITY, &index_key, &())?;

        batch.commit().await?;

        info!("Recovery machine enrolled: {}", recovery_machine_key.machine_id);
        Ok(recovery_machine_key.machine_id)
    }

    async fn create_namespace(
        &self,
        namespace_id: Uuid,
        name: String,
        owner_identity_id: Uuid,
    ) -> Result<Namespace> {
        let namespace = Namespace {
            namespace_id,
            name,
            created_at: current_timestamp(),
            owner_identity_id,
            active: true,
        };

        self.storage
            .put(CF_NAMESPACES, &namespace_id, &namespace)
            .await?;

        Ok(namespace)
    }

    async fn get_namespace(&self, namespace_id: Uuid) -> Result<Namespace> {
        self.storage
            .get(CF_NAMESPACES, &namespace_id)
            .await?
            .ok_or(IdentityCoreError::NotFound(namespace_id))
    }

    async fn get_namespace_membership(
        &self,
        identity_id: Uuid,
        namespace_id: Uuid,
    ) -> Result<Option<IdentityNamespaceMembership>> {
        let key = (identity_id, namespace_id);
        Ok(self
            .storage
            .get(CF_IDENTITY_NAMESPACE_MEMBERSHIPS, &key)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::mocks::MockEventPublisher;
    use zero_auth_crypto::{derive_central_public_key, NeuralKey, MachineKeyCapabilities};
    use zero_auth_policy::PolicyEngineImpl;
    use zero_auth_storage::RocksDbStorage;

    #[tokio::test]
    async fn test_create_identity() {
        let storage = Arc::new(RocksDbStorage::open_test().unwrap());
        let policy = Arc::new(PolicyEngineImpl::new());
        let events = Arc::new(MockEventPublisher);
        let service = IdentityCoreService::new(policy, events, storage);

        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = Uuid::new_v4();
        let (central_public_key, identity_keypair) =
            derive_central_public_key(&neural_key, &identity_id).unwrap();

        let machine_id = Uuid::new_v4();
        let machine_key = MachineKey {
            machine_id,
            identity_id,
            namespace_id: identity_id, // Personal namespace
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
        };

        let message = canonicalize_identity_creation_message(
            &identity_id,
            &central_public_key,
            &machine_id,
            &machine_key.signing_public_key,
            &machine_key.encryption_public_key,
            machine_key.created_at,
        );

        use zero_auth_crypto::sign_message;
        let signature = sign_message(&identity_keypair, &message);

        let request = CreateIdentityRequest {
            identity_id,
            central_public_key,
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
