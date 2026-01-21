//! Identity CRUD operations.

use crate::{errors::*, traits::EventPublisher, types::*};
use tracing::info;
use uuid::Uuid;
use zero_auth_crypto::{canonicalize_identity_creation_message, verify_signature};
use zero_auth_policy::PolicyEngine;
use zero_auth_storage::{
    traits::BatchExt, Storage, CF_IDENTITIES, CF_IDENTITY_NAMESPACE_MEMBERSHIPS, CF_MACHINE_KEYS,
    CF_MACHINE_KEYS_BY_IDENTITY, CF_NAMESPACES, CF_NAMESPACES_BY_IDENTITY,
};

use super::IdentityCoreService;

impl<P, E, S> IdentityCoreService<P, E, S>
where
    P: PolicyEngine + 'static,
    E: EventPublisher + 'static,
    S: Storage + 'static,
{
    /// Create a new identity with its default personal namespace and initial machine key
    pub(crate) async fn create_identity_internal(
        &self,
        request: CreateIdentityRequest,
    ) -> Result<Identity> {
        info!("Creating identity: {}", request.identity_id);
        self.validate_identity_creation_policy(&request).await?;
        Self::verify_identity_authorization(&request)?;
        let (identity, namespace, membership) = Self::build_identity_entities(&request);
        self.persist_identity_batch(&identity, &namespace, &membership, &request.machine_key)
            .await?;

        info!("Identity created successfully: {}", identity.identity_id);
        Ok(identity)
    }

    /// Get an identity by ID
    pub(crate) async fn get_identity_internal(&self, identity_id: Uuid) -> Result<Identity> {
        self.storage
            .get(CF_IDENTITIES, &identity_id)
            .await?
            .ok_or(IdentityCoreError::NotFound(identity_id))
    }

    /// Disable an identity
    pub(crate) async fn disable_identity_internal(&self, identity_id: Uuid) -> Result<()> {
        let mut identity = self.get_identity_internal(identity_id).await?;
        identity.status = IdentityStatus::Disabled;
        identity.updated_at = current_timestamp();

        self.storage
            .put(CF_IDENTITIES, &identity_id, &identity)
            .await?;

        info!("Identity disabled: {}", identity_id);
        Ok(())
    }

    /// Enable a disabled identity
    pub(crate) async fn enable_identity_internal(&self, identity_id: Uuid) -> Result<()> {
        let mut identity = self.get_identity_internal(identity_id).await?;

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

    async fn validate_identity_creation_policy(
        &self,
        request: &CreateIdentityRequest,
    ) -> Result<()> {
        let policy_context = zero_auth_policy::PolicyContext {
            identity_id: request.identity_id,
            machine_id: Some(request.machine_key.machine_id),
            namespace_id: request.identity_id,
            auth_method: zero_auth_policy::AuthMethod::MachineKey,
            mfa_verified: false,
            operation: zero_auth_policy::Operation::CreateIdentity,
            resource: Some(zero_auth_policy::Resource::Identity(request.identity_id)),
            ip_address: "0.0.0.0".to_string(),
            user_agent: "zero-auth-client".to_string(),
            timestamp: request.created_at,
            reputation_score: 50,
            recent_failed_attempts: 0,
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

    fn verify_identity_authorization(request: &CreateIdentityRequest) -> Result<()> {
        let message = canonicalize_identity_creation_message(
            &request.identity_id,
            &request.identity_signing_public_key,
            &request.machine_key.machine_id,
            &request.machine_key.signing_public_key,
            &request.machine_key.encryption_public_key,
            request.created_at,
        );

        verify_signature(
            &request.identity_signing_public_key,
            &message,
            &request
                .authorization_signature
                .as_slice()
                .try_into()
                .map_err(|_| IdentityCoreError::InvalidAuthorizationSignature)?,
        )?;

        Ok(())
    }

    fn build_identity_entities(
        request: &CreateIdentityRequest,
    ) -> (Identity, Namespace, IdentityNamespaceMembership) {
        let identity = Identity {
            identity_id: request.identity_id,
            identity_signing_public_key: request.identity_signing_public_key,
            status: IdentityStatus::Active,
            created_at: request.created_at,
            updated_at: request.created_at,
            frozen_at: None,
            frozen_reason: None,
        };

        let namespace = Namespace {
            namespace_id: request.identity_id,
            name: request
                .namespace_name
                .clone()
                .unwrap_or_else(|| format!("personal-{}", request.identity_id)),
            created_at: request.created_at,
            owner_identity_id: request.identity_id,
            active: true,
        };

        let membership = IdentityNamespaceMembership {
            identity_id: request.identity_id,
            namespace_id: namespace.namespace_id,
            role: NamespaceRole::Owner,
            joined_at: request.created_at,
        };

        (identity, namespace, membership)
    }

    async fn persist_identity_batch(
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

        // Add namespaces-by-identity index for efficient list_namespaces queries
        let ns_index_key = (identity.identity_id, namespace.namespace_id);
        batch.put(CF_NAMESPACES_BY_IDENTITY, &ns_index_key, &())?;

        batch.put(CF_MACHINE_KEYS, &machine_key.machine_id, machine_key)?;

        let index_key = (identity.identity_id, machine_key.machine_id);
        batch.put(CF_MACHINE_KEYS_BY_IDENTITY, &index_key, &())?;

        batch.commit().await?;
        Ok(())
    }
}
