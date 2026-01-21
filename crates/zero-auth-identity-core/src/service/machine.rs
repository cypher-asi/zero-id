//! Machine key operations: enroll, get, list.

use crate::{errors::*, traits::EventPublisher, types::*};
use tracing::info;
use uuid::Uuid;
use zero_auth_crypto::{canonicalize_enrollment_message, verify_signature};
use zero_auth_policy::PolicyEngine;
use zero_auth_storage::{
    traits::BatchExt, Storage, CF_IDENTITIES, CF_MACHINE_KEYS, CF_MACHINE_KEYS_BY_IDENTITY,
    CF_NAMESPACES,
};

use super::IdentityCoreService;

impl<P, E, S> IdentityCoreService<P, E, S>
where
    P: PolicyEngine + 'static,
    E: EventPublisher + 'static,
    S: Storage + 'static,
{
    /// Enroll a new machine key for an identity
    pub(crate) async fn enroll_machine_key_internal(
        &self,
        identity_id: Uuid,
        machine_key: MachineKey,
        authorization_signature: Vec<u8>,
        mfa_verified: bool,
        ip_address: String,
        user_agent: String,
    ) -> Result<Uuid> {
        let reputation_score = self.policy.get_reputation(identity_id).await.unwrap_or(50);

        // Fetch identity for status check
        let identity: Option<Identity> = self.storage.get(CF_IDENTITIES, &identity_id).await?;
        let namespace: Option<Namespace> = self.storage.get(CF_NAMESPACES, &machine_key.namespace_id).await?;

        let policy_context = zero_auth_policy::PolicyContext {
            identity_id,
            machine_id: Some(machine_key.machine_id),
            namespace_id: machine_key.namespace_id,
            auth_method: zero_auth_policy::AuthMethod::MachineKey,
            mfa_verified,
            operation: zero_auth_policy::Operation::EnrollMachine,
            resource: Some(zero_auth_policy::Resource::Machine(machine_key.machine_id)),
            ip_address,
            user_agent,
            timestamp: machine_key.created_at,
            reputation_score,
            recent_failed_attempts: 0,
            identity_status: identity.as_ref().map(|i| match i.status {
                IdentityStatus::Active => zero_auth_policy::IdentityStatus::Active,
                IdentityStatus::Disabled => zero_auth_policy::IdentityStatus::Disabled,
                IdentityStatus::Frozen => zero_auth_policy::IdentityStatus::Frozen,
                IdentityStatus::Deleted => zero_auth_policy::IdentityStatus::Deleted,
            }),
            machine_revoked: None, // New machine being enrolled
            machine_capabilities: Some(machine_key.capabilities.bits()),
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

        let identity = self.get_identity_internal(identity_id).await?;

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
            &identity.identity_signing_public_key,
            &message,
            &authorization_signature
                .as_slice()
                .try_into()
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

    /// Get a machine key by ID
    pub(crate) async fn get_machine_key_internal(&self, machine_id: Uuid) -> Result<MachineKey> {
        self.storage
            .get(CF_MACHINE_KEYS, &machine_id)
            .await?
            .ok_or(IdentityCoreError::MachineNotFound(machine_id))
    }

    /// List machines for an identity in a specific namespace
    pub(crate) async fn list_machines_internal(
        &self,
        identity_id: Uuid,
        namespace_id: Uuid,
    ) -> Result<Vec<MachineKey>> {
        let all_machines = self.list_active_machines(identity_id).await?;

        let machines: Vec<MachineKey> = all_machines
            .into_iter()
            .filter(|m| m.namespace_id == namespace_id)
            .collect();

        Ok(machines)
    }
}
