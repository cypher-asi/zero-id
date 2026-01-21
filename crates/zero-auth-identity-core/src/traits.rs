//! Identity Core trait definitions.

use crate::{errors::Result, types::*};
use async_trait::async_trait;
use uuid::Uuid;

/// Event publisher trait for publishing revocation events
///
/// This trait is injected into Identity Core to avoid circular dependencies
/// with the Integrations subsystem.
#[async_trait]
pub trait EventPublisher: Send + Sync {
    /// Publish a revocation event
    async fn publish(&self, event: RevocationEvent) -> Result<()>;
}

/// Identity Core subsystem trait
#[async_trait]
pub trait IdentityCore: Send + Sync {
    /// Create a new identity with Neural Key authorization
    async fn create_identity(&self, request: CreateIdentityRequest) -> Result<Identity>;

    /// Get identity by ID
    async fn get_identity(&self, identity_id: Uuid) -> Result<Identity>;

    /// Disable an identity (soft delete)
    async fn disable_identity(&self, identity_id: Uuid) -> Result<()>;

    /// Re-enable a disabled identity
    async fn enable_identity(&self, identity_id: Uuid) -> Result<()>;

    /// Freeze an identity (security lockdown, requires approvals)
    async fn freeze_identity(
        &self,
        identity_id: Uuid,
        reason: FreezeReason,
        approvals: Vec<Approval>,
    ) -> Result<()>;

    /// Unfreeze an identity (requires ceremony)
    async fn unfreeze_identity(&self, identity_id: Uuid, approvals: Vec<Approval>) -> Result<()>;

    /// Enroll a new Machine Key for an identity
    async fn enroll_machine_key(
        &self,
        identity_id: Uuid,
        machine_key: MachineKey,
        authorization_signature: Vec<u8>,
        mfa_verified: bool,
        ip_address: String,
        user_agent: String,
    ) -> Result<Uuid>;

    /// Get Machine Key by ID
    async fn get_machine_key(&self, machine_id: Uuid) -> Result<MachineKey>;

    /// List all Machine Keys for an identity in a namespace
    async fn list_machines(&self, identity_id: Uuid, namespace_id: Uuid)
        -> Result<Vec<MachineKey>>;

    /// Revoke a Machine Key
    async fn revoke_machine_key(
        &self,
        machine_id: Uuid,
        revoked_by: Uuid,
        reason: String,
        mfa_verified: bool,
        ip_address: String,
        user_agent: String,
    ) -> Result<()>;

    /// Rotate Neural Key (requires multi-machine approval)
    async fn rotate_neural_key(&self, request: RotationRequest) -> Result<()>;

    /// Initiate Neural Key recovery
    async fn initiate_recovery(
        &self,
        identity_id: Uuid,
        recovery_machine_key: MachineKey,
        approvals: Vec<Approval>,
    ) -> Result<Uuid>;

    /// Create a namespace
    async fn create_namespace(
        &self,
        namespace_id: Uuid,
        name: String,
        owner_identity_id: Uuid,
    ) -> Result<Namespace>;

    /// Get namespace by ID
    async fn get_namespace(&self, namespace_id: Uuid) -> Result<Namespace>;

    /// Get namespace membership
    async fn get_namespace_membership(
        &self,
        identity_id: Uuid,
        namespace_id: Uuid,
    ) -> Result<Option<IdentityNamespaceMembership>>;

    // ========================================================================
    // Namespace Management
    // ========================================================================

    /// List all namespaces for an identity
    async fn list_namespaces(&self, identity_id: Uuid) -> Result<Vec<Namespace>>;

    /// Update a namespace (name)
    async fn update_namespace(
        &self,
        namespace_id: Uuid,
        name: String,
        requester_id: Uuid,
    ) -> Result<Namespace>;

    /// Deactivate a namespace
    async fn deactivate_namespace(
        &self,
        namespace_id: Uuid,
        requester_id: Uuid,
    ) -> Result<()>;

    /// Reactivate a namespace
    async fn reactivate_namespace(
        &self,
        namespace_id: Uuid,
        requester_id: Uuid,
    ) -> Result<()>;

    /// Delete a namespace (must have no other members)
    async fn delete_namespace(
        &self,
        namespace_id: Uuid,
        requester_id: Uuid,
    ) -> Result<()>;

    // ========================================================================
    // Namespace Membership Management
    // ========================================================================

    /// List all members of a namespace
    async fn list_namespace_members(
        &self,
        namespace_id: Uuid,
        requester_id: Uuid,
    ) -> Result<Vec<IdentityNamespaceMembership>>;

    /// Add a member to a namespace
    async fn add_namespace_member(
        &self,
        namespace_id: Uuid,
        identity_id: Uuid,
        role: NamespaceRole,
        requester_id: Uuid,
    ) -> Result<IdentityNamespaceMembership>;

    /// Update a member's role in a namespace
    async fn update_namespace_member(
        &self,
        namespace_id: Uuid,
        identity_id: Uuid,
        role: NamespaceRole,
        requester_id: Uuid,
    ) -> Result<IdentityNamespaceMembership>;

    /// Remove a member from a namespace
    async fn remove_namespace_member(
        &self,
        namespace_id: Uuid,
        identity_id: Uuid,
        requester_id: Uuid,
    ) -> Result<()>;
}

#[cfg(test)]
pub mod mocks {
    use super::*;

    /// Mock event publisher for testing
    pub struct MockEventPublisher;

    #[async_trait]
    impl EventPublisher for MockEventPublisher {
        async fn publish(&self, _event: RevocationEvent) -> Result<()> {
            Ok(())
        }
    }
}
