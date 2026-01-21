//! Namespace operations: create, get, membership.

use crate::{errors::*, traits::EventPublisher, types::*};
use uuid::Uuid;
use zero_auth_policy::PolicyEngine;
use zero_auth_storage::{Storage, CF_IDENTITY_NAMESPACE_MEMBERSHIPS, CF_NAMESPACES};

use super::IdentityCoreService;

impl<P, E, S> IdentityCoreService<P, E, S>
where
    P: PolicyEngine + 'static,
    E: EventPublisher + 'static,
    S: Storage + 'static,
{
    /// Create a new namespace
    pub(crate) async fn create_namespace_internal(
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

    /// Get a namespace by ID
    pub(crate) async fn get_namespace_internal(&self, namespace_id: Uuid) -> Result<Namespace> {
        self.storage
            .get(CF_NAMESPACES, &namespace_id)
            .await?
            .ok_or(IdentityCoreError::NotFound(namespace_id))
    }

    /// Get namespace membership for an identity
    pub(crate) async fn get_namespace_membership_internal(
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
