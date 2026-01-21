//! Identity ceremonies: freeze, unfreeze, rotate, recovery operations.

use crate::{errors::*, traits::IdentityCore, types::*};
use std::collections::HashSet;
use tracing::info;
use uuid::Uuid;
use zero_auth_policy::PolicyEngine;
use zero_auth_storage::{
    traits::BatchExt, Storage, CF_IDENTITIES, CF_MACHINE_KEYS, CF_MACHINE_KEYS_BY_IDENTITY,
    CF_NAMESPACES,
};

use super::{EventPublisher, IdentityCoreService};

impl<P, E, S> IdentityCoreService<P, E, S>
where
    P: PolicyEngine + 'static,
    E: EventPublisher + 'static,
    S: Storage + 'static,
{
    /// Freeze an identity (internal implementation)
    pub(super) async fn freeze_identity_internal(
        &self,
        identity_id: Uuid,
        reason: FreezeReason,
        approvals: Vec<Approval>,
    ) -> Result<()> {
        let identity = self.get_identity(identity_id).await?;

        if identity.status == IdentityStatus::Frozen {
            return Err(IdentityCoreError::AlreadyFrozen(identity_id));
        }

        let active_machines = self.list_active_machines(identity_id).await?;

        if approvals.is_empty() {
            return Err(IdentityCoreError::InsufficientApprovals {
                required: 1,
                provided: 0,
            });
        }

        let message = Self::build_freeze_message(identity_id, &reason, &approvals);
        self.verify_approval_signatures(&message, &approvals, &active_machines)?;

        self.persist_freeze(identity_id, identity, &reason).await
    }

    /// Unfreeze an identity (internal implementation)
    pub(super) async fn unfreeze_identity_internal(
        &self,
        identity_id: Uuid,
        approvals: Vec<Approval>,
    ) -> Result<()> {
        let identity = self.get_identity(identity_id).await?;

        if identity.status != IdentityStatus::Frozen {
            return Err(IdentityCoreError::NotFrozen(identity_id));
        }

        let active_machines = self.list_active_machines(identity_id).await?;

        let required_approvals = if active_machines.len() >= 2 { 2 } else { 1 };

        if approvals.len() < required_approvals {
            return Err(IdentityCoreError::InsufficientApprovals {
                required: required_approvals,
                provided: approvals.len(),
            });
        }

        // Build message for signature verification
        let mut message = Vec::with_capacity(8 + 16 + 8);
        message.extend_from_slice(b"unfreeze");
        message.extend_from_slice(identity_id.as_bytes());

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

    /// Revoke a machine key (internal implementation)
    pub(super) async fn revoke_machine_key_internal(
        &self,
        machine_id: Uuid,
        revoked_by: Uuid,
        reason: String,
        mfa_verified: bool,
        ip_address: String,
        user_agent: String,
    ) -> Result<()> {
        let mut machine = self.get_machine_key(machine_id).await?;

        if machine.revoked {
            return Err(IdentityCoreError::AlreadyRevoked(machine_id));
        }

        Self::validate_revocation_permission(&machine, revoked_by)?;
        self.evaluate_revocation_policy(
            &machine,
            machine_id,
            mfa_verified,
            &ip_address,
            &user_agent,
        )
        .await?;
        self.persist_revocation(machine_id, &mut machine, &reason)
            .await
    }

    /// Rotate neural key (internal implementation)
    pub(super) async fn rotate_neural_key_internal(&self, request: RotationRequest) -> Result<()> {
        let identity = self.get_identity(request.identity_id).await?;

        if request.approvals.len() < 2 {
            return Err(IdentityCoreError::InsufficientApprovals {
                required: 2,
                provided: request.approvals.len(),
            });
        }

        let active_machines = self.list_active_machines(request.identity_id).await?;

        let RotationRequest {
            identity_id,
            new_identity_signing_public_key,
            new_machines,
            approvals,
        } = request;

        self.validate_rotation_approvals(
            identity_id,
            &new_identity_signing_public_key,
            &approvals,
            &active_machines,
        )?;
        self.execute_rotation_batch(
            identity,
            identity_id,
            new_identity_signing_public_key,
            new_machines,
            active_machines,
        )
        .await
    }

    /// Initiate recovery (internal implementation)
    pub(super) async fn initiate_recovery_internal(
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

        // Verify approvals if required
        if approval_required {
            let mut message = Vec::with_capacity(8 + 16 + 16 + 8);
            message.extend_from_slice(b"recovery");
            message.extend_from_slice(identity_id.as_bytes());
            message.extend_from_slice(recovery_machine_key.machine_id.as_bytes());

            if let Some(first_approval) = approvals.first() {
                message.extend_from_slice(&first_approval.timestamp.to_be_bytes());
            }

            self.verify_approval_signatures(&message, &approvals, &active_machines)?;
        }

        // Enroll recovery machine
        let mut batch = self.storage.batch();

        batch.put(
            CF_MACHINE_KEYS,
            &recovery_machine_key.machine_id,
            &recovery_machine_key,
        )?;

        let index_key = (identity_id, recovery_machine_key.machine_id);
        batch.put(CF_MACHINE_KEYS_BY_IDENTITY, &index_key, &())?;

        batch.commit().await?;

        info!(
            "Recovery machine enrolled: {}",
            recovery_machine_key.machine_id
        );
        Ok(recovery_machine_key.machine_id)
    }

    fn build_freeze_message(
        identity_id: Uuid,
        reason: &FreezeReason,
        approvals: &[Approval],
    ) -> Vec<u8> {
        let mut message = Vec::with_capacity(6 + 16 + reason.to_string().len() + 8);
        message.extend_from_slice(b"freeze");
        message.extend_from_slice(identity_id.as_bytes());
        message.extend_from_slice(reason.to_string().as_bytes());

        if let Some(first_approval) = approvals.first() {
            message.extend_from_slice(&first_approval.timestamp.to_be_bytes());
        }

        message
    }

    async fn persist_freeze(
        &self,
        identity_id: Uuid,
        identity: Identity,
        reason: &FreezeReason,
    ) -> Result<()> {
        let mut updated_identity = identity;
        updated_identity.status = IdentityStatus::Frozen;
        updated_identity.frozen_at = Some(current_timestamp());
        updated_identity.frozen_reason = Some(reason.to_string());
        updated_identity.updated_at = current_timestamp();

        self.storage
            .put(CF_IDENTITIES, &identity_id, &updated_identity)
            .await?;

        let sequence = self.next_event_sequence(identity_id).await?;
        self.event_publisher
            .publish(RevocationEvent {
                event_id: Uuid::new_v4(),
                event_type: EventType::IdentityFrozen,
                namespace_id: identity_id,
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

    fn validate_revocation_permission(machine: &MachineKey, revoked_by: Uuid) -> Result<()> {
        if revoked_by != machine.identity_id && revoked_by != machine.machine_id {
            return Err(IdentityCoreError::Other(
                "Not authorized to revoke this machine".to_string(),
            ));
        }

        Ok(())
    }

    async fn evaluate_revocation_policy(
        &self,
        machine: &MachineKey,
        machine_id: Uuid,
        mfa_verified: bool,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<()> {
        let reputation_score = self
            .policy
            .get_reputation(machine.identity_id)
            .await
            .unwrap_or(50);

        // Fetch entity states for policy evaluation
        let identity: Option<Identity> = self.storage.get(CF_IDENTITIES, &machine.identity_id).await?;
        let namespace: Option<Namespace> = self.storage.get(CF_NAMESPACES, &machine.namespace_id).await?;

        let policy_context = zero_auth_policy::PolicyContext {
            identity_id: machine.identity_id,
            machine_id: Some(machine_id),
            namespace_id: machine.namespace_id,
            auth_method: zero_auth_policy::AuthMethod::MachineKey,
            mfa_verified,
            operation: zero_auth_policy::Operation::RevokeMachine,
            resource: Some(zero_auth_policy::Resource::Machine(machine_id)),
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            timestamp: current_timestamp(),
            reputation_score,
            recent_failed_attempts: 0,
            identity_status: identity.as_ref().map(|i| match i.status {
                IdentityStatus::Active => zero_auth_policy::IdentityStatus::Active,
                IdentityStatus::Disabled => zero_auth_policy::IdentityStatus::Disabled,
                IdentityStatus::Frozen => zero_auth_policy::IdentityStatus::Frozen,
                IdentityStatus::Deleted => zero_auth_policy::IdentityStatus::Deleted,
            }),
            machine_revoked: Some(machine.revoked),
            machine_capabilities: Some(machine.capabilities.bits()),
            namespace_active: namespace.as_ref().map(|n| n.active),
        };

        let decision =
            self.policy.evaluate(policy_context).await.map_err(|e| {
                IdentityCoreError::Other(format!("Policy evaluation failed: {}", e))
            })?;

        if decision.verdict != zero_auth_policy::Verdict::Allow {
            return Err(IdentityCoreError::Other(format!(
                "Policy denied operation: {}",
                decision.reason
            )));
        }

        Ok(())
    }

    async fn persist_revocation(
        &self,
        machine_id: Uuid,
        machine: &mut MachineKey,
        reason: &str,
    ) -> Result<()> {
        machine.revoked = true;
        machine.revoked_at = Some(current_timestamp());

        self.storage
            .put(CF_MACHINE_KEYS, &machine_id, machine)
            .await?;

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
                reason: reason.to_string(),
            })
            .await?;

        info!("Machine key revoked: {}, reason: {}", machine_id, reason);
        Ok(())
    }

    fn validate_rotation_approvals(
        &self,
        identity_id: Uuid,
        new_identity_signing_public_key: &[u8],
        approvals: &[Approval],
        active_machines: &[MachineKey],
    ) -> Result<()> {
        let mut approving_machines = HashSet::new();
        for approval in approvals {
            if !approving_machines.insert(approval.machine_id) {
                return Err(IdentityCoreError::DuplicateApproval(approval.machine_id));
            }
        }

        let mut message = Vec::with_capacity(6 + 16 + 32 + 8);
        message.extend_from_slice(b"rotate");
        message.extend_from_slice(identity_id.as_bytes());
        message.extend_from_slice(new_identity_signing_public_key);

        if let Some(first_approval) = approvals.first() {
            message.extend_from_slice(&first_approval.timestamp.to_be_bytes());
        }

        self.verify_approval_signatures(&message, approvals, active_machines)?;
        Ok(())
    }

    async fn execute_rotation_batch(
        &self,
        identity: Identity,
        identity_id: Uuid,
        new_identity_signing_public_key: [u8; 32],
        new_machines: Vec<MachineKey>,
        active_machines: Vec<MachineKey>,
    ) -> Result<()> {
        let mut batch = self.storage.batch();

        let mut updated_identity = identity;
        updated_identity.identity_signing_public_key = new_identity_signing_public_key;
        updated_identity.updated_at = current_timestamp();
        batch.put(
            CF_IDENTITIES,
            &updated_identity.identity_id,
            &updated_identity,
        )?;

        for machine in active_machines {
            let mut revoked_machine = machine;
            revoked_machine.revoked = true;
            revoked_machine.revoked_at = Some(current_timestamp());
            batch.put(
                CF_MACHINE_KEYS,
                &revoked_machine.machine_id,
                &revoked_machine,
            )?;
        }

        for new_machine in new_machines {
            batch.put(CF_MACHINE_KEYS, &new_machine.machine_id, &new_machine)?;
            let index_key = (identity_id, new_machine.machine_id);
            batch.put(CF_MACHINE_KEYS_BY_IDENTITY, &index_key, &())?;
        }

        batch.commit().await?;

        info!("Neural key rotated for identity: {}", identity_id);
        Ok(())
    }
}
