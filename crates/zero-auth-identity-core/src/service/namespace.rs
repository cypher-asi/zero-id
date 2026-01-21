//! Namespace operations: create, get, update, delete, membership management.

use crate::{errors::*, traits::EventPublisher, types::*};
use tracing::info;
use uuid::Uuid;
use zero_auth_policy::PolicyEngine;
use zero_auth_storage::{
    traits::BatchExt, Storage, CF_IDENTITY_NAMESPACE_MEMBERSHIPS, CF_NAMESPACES,
    CF_NAMESPACES_BY_IDENTITY,
};

use super::IdentityCoreService;

// ============================================================================
// Authorization Helpers
// ============================================================================

/// Check if a role can manage members (add/update/remove)
fn can_manage_members(role: NamespaceRole) -> bool {
    matches!(role, NamespaceRole::Owner | NamespaceRole::Admin)
}

/// Check if a role can modify namespace settings
fn can_modify_namespace(role: NamespaceRole) -> bool {
    role == NamespaceRole::Owner
}

impl<P, E, S> IdentityCoreService<P, E, S>
where
    P: PolicyEngine + 'static,
    E: EventPublisher + 'static,
    S: Storage + 'static,
{
    // ========================================================================
    // Namespace CRUD Operations
    // ========================================================================

    /// Create a new namespace with owner membership
    pub(crate) async fn create_namespace_internal(
        &self,
        namespace_id: Uuid,
        name: String,
        owner_identity_id: Uuid,
    ) -> Result<Namespace> {
        // Check if namespace already exists
        if self
            .storage
            .get::<Uuid, Namespace>(CF_NAMESPACES, &namespace_id)
            .await?
            .is_some()
        {
            return Err(IdentityCoreError::NamespaceAlreadyExists(namespace_id));
        }

        // Verify owner identity exists
        self.get_identity_internal(owner_identity_id).await?;

        let now = current_timestamp();

        let namespace = Namespace {
            namespace_id,
            name,
            created_at: now,
            owner_identity_id,
            active: true,
        };

        // Create owner membership
        let membership = IdentityNamespaceMembership {
            identity_id: owner_identity_id,
            namespace_id,
            role: NamespaceRole::Owner,
            joined_at: now,
        };

        // Persist namespace, membership, and index in a batch
        let mut batch = self.storage.batch();

        batch.put(CF_NAMESPACES, &namespace_id, &namespace)?;

        let membership_key = (owner_identity_id, namespace_id);
        batch.put(CF_IDENTITY_NAMESPACE_MEMBERSHIPS, &membership_key, &membership)?;

        // Add to namespaces-by-identity index
        let index_key = (owner_identity_id, namespace_id);
        batch.put(CF_NAMESPACES_BY_IDENTITY, &index_key, &())?;

        batch.commit().await?;

        info!(
            "Namespace created: {} by owner {}",
            namespace_id, owner_identity_id
        );

        Ok(namespace)
    }

    /// Get a namespace by ID
    pub(crate) async fn get_namespace_internal(&self, namespace_id: Uuid) -> Result<Namespace> {
        self.storage
            .get(CF_NAMESPACES, &namespace_id)
            .await?
            .ok_or(IdentityCoreError::NamespaceNotFound(namespace_id))
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

    /// List all namespaces for an identity
    pub(crate) async fn list_namespaces_internal(
        &self,
        identity_id: Uuid,
    ) -> Result<Vec<Namespace>> {
        // Query the namespaces-by-identity index
        let index_entries: Vec<(Vec<u8>, ())> = self
            .storage
            .get_by_prefix(CF_NAMESPACES_BY_IDENTITY, &identity_id)
            .await?;

        let mut namespaces = Vec::new();

        for (key_bytes, _) in index_entries {
            // Key format with bincode serialization:
            // - 8 bytes: length prefix for first Uuid (always 16)
            // - 16 bytes: identity_id
            // - 8 bytes: length prefix for second Uuid (always 16)
            // - 16 bytes: namespace_id
            // Total: 48 bytes
            if key_bytes.len() >= 48 {
                let namespace_id_bytes = &key_bytes[32..48];
                let namespace_id = Uuid::from_slice(namespace_id_bytes).map_err(|e| {
                    IdentityCoreError::Storage(zero_auth_storage::StorageError::Deserialization(
                        e.to_string(),
                    ))
                })?;

                if let Some(namespace) = self.storage.get(CF_NAMESPACES, &namespace_id).await? {
                    namespaces.push(namespace);
                }
            }
        }

        Ok(namespaces)
    }

    /// Update a namespace (name only)
    pub(crate) async fn update_namespace_internal(
        &self,
        namespace_id: Uuid,
        name: String,
        requester_id: Uuid,
    ) -> Result<Namespace> {
        let mut namespace = self.get_namespace_internal(namespace_id).await?;

        // Check authorization - only owner can modify
        let membership = self
            .get_namespace_membership_internal(requester_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::NotNamespaceMember {
                identity_id: requester_id,
                namespace_id,
            })?;

        if !can_modify_namespace(membership.role) {
            return Err(IdentityCoreError::InsufficientPermissions {
                role: membership.role,
                action: "update namespace".to_string(),
            });
        }

        namespace.name = name;

        self.storage
            .put(CF_NAMESPACES, &namespace_id, &namespace)
            .await?;

        info!("Namespace {} updated by {}", namespace_id, requester_id);

        Ok(namespace)
    }

    /// Deactivate a namespace
    pub(crate) async fn deactivate_namespace_internal(
        &self,
        namespace_id: Uuid,
        requester_id: Uuid,
    ) -> Result<()> {
        let mut namespace = self.get_namespace_internal(namespace_id).await?;

        // Check authorization - only owner can deactivate
        let membership = self
            .get_namespace_membership_internal(requester_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::NotNamespaceMember {
                identity_id: requester_id,
                namespace_id,
            })?;

        if !can_modify_namespace(membership.role) {
            return Err(IdentityCoreError::InsufficientPermissions {
                role: membership.role,
                action: "deactivate namespace".to_string(),
            });
        }

        namespace.active = false;

        self.storage
            .put(CF_NAMESPACES, &namespace_id, &namespace)
            .await?;

        info!("Namespace {} deactivated by {}", namespace_id, requester_id);

        Ok(())
    }

    /// Reactivate a namespace
    pub(crate) async fn reactivate_namespace_internal(
        &self,
        namespace_id: Uuid,
        requester_id: Uuid,
    ) -> Result<()> {
        let mut namespace = self.get_namespace_internal(namespace_id).await?;

        // Check authorization - only owner can reactivate
        let membership = self
            .get_namespace_membership_internal(requester_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::NotNamespaceMember {
                identity_id: requester_id,
                namespace_id,
            })?;

        if !can_modify_namespace(membership.role) {
            return Err(IdentityCoreError::InsufficientPermissions {
                role: membership.role,
                action: "reactivate namespace".to_string(),
            });
        }

        namespace.active = true;

        self.storage
            .put(CF_NAMESPACES, &namespace_id, &namespace)
            .await?;

        info!("Namespace {} reactivated by {}", namespace_id, requester_id);

        Ok(())
    }

    /// Delete a namespace (must have no other members)
    pub(crate) async fn delete_namespace_internal(
        &self,
        namespace_id: Uuid,
        requester_id: Uuid,
    ) -> Result<()> {
        let namespace = self.get_namespace_internal(namespace_id).await?;

        // Check authorization - only owner can delete
        let membership = self
            .get_namespace_membership_internal(requester_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::NotNamespaceMember {
                identity_id: requester_id,
                namespace_id,
            })?;

        if !can_modify_namespace(membership.role) {
            return Err(IdentityCoreError::InsufficientPermissions {
                role: membership.role,
                action: "delete namespace".to_string(),
            });
        }

        // Check that namespace has no other members
        let members = self
            .list_namespace_members_internal(namespace_id, requester_id)
            .await?;
        if members.len() > 1 {
            return Err(IdentityCoreError::NamespaceHasMembers(namespace_id));
        }

        // Delete namespace, membership, and index in a batch
        let mut batch = self.storage.batch();

        batch.delete(CF_NAMESPACES, &namespace_id)?;

        let membership_key = (namespace.owner_identity_id, namespace_id);
        batch.delete(CF_IDENTITY_NAMESPACE_MEMBERSHIPS, &membership_key)?;

        let index_key = (namespace.owner_identity_id, namespace_id);
        batch.delete(CF_NAMESPACES_BY_IDENTITY, &index_key)?;

        batch.commit().await?;

        info!("Namespace {} deleted by {}", namespace_id, requester_id);

        Ok(())
    }

    // ========================================================================
    // Membership Management
    // ========================================================================

    /// List all members of a namespace
    pub(crate) async fn list_namespace_members_internal(
        &self,
        namespace_id: Uuid,
        requester_id: Uuid,
    ) -> Result<Vec<IdentityNamespaceMembership>> {
        // Verify namespace exists
        let namespace = self.get_namespace_internal(namespace_id).await?;

        // Check that namespace is active
        if !namespace.active {
            return Err(IdentityCoreError::NamespaceNotActive(namespace_id));
        }

        // Check requester is a member
        self.get_namespace_membership_internal(requester_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::NotNamespaceMember {
                identity_id: requester_id,
                namespace_id,
            })?;

        // Get all memberships for this namespace
        // We need to scan by namespace_id, but our key is (identity_id, namespace_id)
        // This requires scanning all memberships - in production, consider adding
        // a reverse index (namespace_id, identity_id) -> ()
        // For now, we'll use a workaround by iterating through known patterns
        
        // A more efficient approach: iterate through namespaces-by-identity in reverse
        // For now, we'll iterate all memberships and filter
        let all_memberships: Vec<(Vec<u8>, IdentityNamespaceMembership)> = self
            .storage
            .scan_all(CF_IDENTITY_NAMESPACE_MEMBERSHIPS)
            .await?;

        let members: Vec<IdentityNamespaceMembership> = all_memberships
            .into_iter()
            .map(|(_, m)| m)
            .filter(|m| m.namespace_id == namespace_id)
            .collect();

        Ok(members)
    }

    /// Add a member to a namespace
    pub(crate) async fn add_namespace_member_internal(
        &self,
        namespace_id: Uuid,
        identity_id: Uuid,
        role: NamespaceRole,
        requester_id: Uuid,
    ) -> Result<IdentityNamespaceMembership> {
        // Verify namespace exists and is active
        let namespace = self.get_namespace_internal(namespace_id).await?;
        if !namespace.active {
            return Err(IdentityCoreError::NamespaceNotActive(namespace_id));
        }

        // Verify target identity exists
        self.get_identity_internal(identity_id).await?;

        // Check authorization - owner/admin can add members
        let requester_membership = self
            .get_namespace_membership_internal(requester_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::NotNamespaceMember {
                identity_id: requester_id,
                namespace_id,
            })?;

        if !can_manage_members(requester_membership.role) {
            return Err(IdentityCoreError::InsufficientPermissions {
                role: requester_membership.role,
                action: "add members".to_string(),
            });
        }

        // Admins can only add Members, not other Admins or Owners
        if requester_membership.role == NamespaceRole::Admin && role != NamespaceRole::Member {
            return Err(IdentityCoreError::InsufficientPermissions {
                role: requester_membership.role,
                action: format!("add {:?} role", role),
            });
        }

        // Cannot add Owner role (there can only be one owner)
        if role == NamespaceRole::Owner {
            return Err(IdentityCoreError::InsufficientPermissions {
                role: requester_membership.role,
                action: "add Owner role".to_string(),
            });
        }

        // Check if member already exists
        if self
            .get_namespace_membership_internal(identity_id, namespace_id)
            .await?
            .is_some()
        {
            return Err(IdentityCoreError::MemberAlreadyExists {
                identity_id,
                namespace_id,
            });
        }

        let now = current_timestamp();
        let membership = IdentityNamespaceMembership {
            identity_id,
            namespace_id,
            role,
            joined_at: now,
        };

        // Persist membership and index
        let mut batch = self.storage.batch();

        let membership_key = (identity_id, namespace_id);
        batch.put(CF_IDENTITY_NAMESPACE_MEMBERSHIPS, &membership_key, &membership)?;

        let index_key = (identity_id, namespace_id);
        batch.put(CF_NAMESPACES_BY_IDENTITY, &index_key, &())?;

        batch.commit().await?;

        info!(
            "Member {} added to namespace {} with role {:?} by {}",
            identity_id, namespace_id, role, requester_id
        );

        Ok(membership)
    }

    /// Update a member's role in a namespace
    pub(crate) async fn update_namespace_member_internal(
        &self,
        namespace_id: Uuid,
        identity_id: Uuid,
        new_role: NamespaceRole,
        requester_id: Uuid,
    ) -> Result<IdentityNamespaceMembership> {
        // Verify namespace exists and is active
        let namespace = self.get_namespace_internal(namespace_id).await?;
        if !namespace.active {
            return Err(IdentityCoreError::NamespaceNotActive(namespace_id));
        }

        // Get target membership
        let mut membership = self
            .get_namespace_membership_internal(identity_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::MemberNotFound {
                identity_id,
                namespace_id,
            })?;

        // Check authorization
        let requester_membership = self
            .get_namespace_membership_internal(requester_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::NotNamespaceMember {
                identity_id: requester_id,
                namespace_id,
            })?;

        if !can_manage_members(requester_membership.role) {
            return Err(IdentityCoreError::InsufficientPermissions {
                role: requester_membership.role,
                action: "update member role".to_string(),
            });
        }

        // Cannot change Owner's role
        if membership.role == NamespaceRole::Owner {
            return Err(IdentityCoreError::CannotRemoveOwner);
        }

        // Cannot promote to Owner
        if new_role == NamespaceRole::Owner {
            return Err(IdentityCoreError::InsufficientPermissions {
                role: requester_membership.role,
                action: "promote to Owner".to_string(),
            });
        }

        // Admins can only manage Members (not other Admins)
        if requester_membership.role == NamespaceRole::Admin {
            if membership.role == NamespaceRole::Admin {
                return Err(IdentityCoreError::InsufficientPermissions {
                    role: requester_membership.role,
                    action: "modify Admin role".to_string(),
                });
            }
            if new_role == NamespaceRole::Admin {
                return Err(IdentityCoreError::InsufficientPermissions {
                    role: requester_membership.role,
                    action: "promote to Admin".to_string(),
                });
            }
        }

        membership.role = new_role;

        let membership_key = (identity_id, namespace_id);
        self.storage
            .put(CF_IDENTITY_NAMESPACE_MEMBERSHIPS, &membership_key, &membership)
            .await?;

        info!(
            "Member {} role updated to {:?} in namespace {} by {}",
            identity_id, new_role, namespace_id, requester_id
        );

        Ok(membership)
    }

    /// Remove a member from a namespace
    pub(crate) async fn remove_namespace_member_internal(
        &self,
        namespace_id: Uuid,
        identity_id: Uuid,
        requester_id: Uuid,
    ) -> Result<()> {
        // Verify namespace exists and is active
        let namespace = self.get_namespace_internal(namespace_id).await?;
        if !namespace.active {
            return Err(IdentityCoreError::NamespaceNotActive(namespace_id));
        }

        // Get target membership
        let membership = self
            .get_namespace_membership_internal(identity_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::MemberNotFound {
                identity_id,
                namespace_id,
            })?;

        // Cannot remove owner
        if membership.role == NamespaceRole::Owner {
            return Err(IdentityCoreError::CannotRemoveOwner);
        }

        // Check authorization
        let requester_membership = self
            .get_namespace_membership_internal(requester_id, namespace_id)
            .await?
            .ok_or(IdentityCoreError::NotNamespaceMember {
                identity_id: requester_id,
                namespace_id,
            })?;

        // Allow self-removal
        if identity_id != requester_id {
            if !can_manage_members(requester_membership.role) {
                return Err(IdentityCoreError::InsufficientPermissions {
                    role: requester_membership.role,
                    action: "remove members".to_string(),
                });
            }

            // Admins cannot remove other Admins
            if requester_membership.role == NamespaceRole::Admin
                && membership.role == NamespaceRole::Admin
            {
                return Err(IdentityCoreError::InsufficientPermissions {
                    role: requester_membership.role,
                    action: "remove Admin".to_string(),
                });
            }
        }

        // Delete membership and index
        let mut batch = self.storage.batch();

        let membership_key = (identity_id, namespace_id);
        batch.delete(CF_IDENTITY_NAMESPACE_MEMBERSHIPS, &membership_key)?;

        let index_key = (identity_id, namespace_id);
        batch.delete(CF_NAMESPACES_BY_IDENTITY, &index_key)?;

        batch.commit().await?;

        info!(
            "Member {} removed from namespace {} by {}",
            identity_id, namespace_id, requester_id
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::mocks::MockEventPublisher;
    use crate::types::{CreateIdentityRequest, MachineKey};
    use std::sync::Arc;
    use zero_auth_crypto::{
        canonicalize_identity_creation_message, derive_identity_signing_keypair, sign_message,
        MachineKeyCapabilities, NeuralKey,
    };
    use zero_auth_policy::PolicyEngineImpl;
    use zero_auth_storage::RocksDbStorage;

    // Helper to create a test service
    fn create_test_service() -> IdentityCoreService<
        PolicyEngineImpl<RocksDbStorage>,
        MockEventPublisher,
        RocksDbStorage,
    > {
        let storage = Arc::new(RocksDbStorage::open_test().unwrap());
        let policy = Arc::new(PolicyEngineImpl::new(Arc::clone(&storage)));
        let events = Arc::new(MockEventPublisher);
        IdentityCoreService::new(policy, events, storage)
    }

    // Helper to create a test identity
    async fn create_test_identity(
        service: &IdentityCoreService<PolicyEngineImpl<RocksDbStorage>, MockEventPublisher, RocksDbStorage>,
    ) -> Uuid {
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

        service.create_identity_internal(request).await.unwrap();
        identity_id
    }

    // ========================================================================
    // Namespace CRUD Tests
    // ========================================================================

    #[tokio::test]
    async fn test_create_namespace_success() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        let namespace = service
            .create_namespace_internal(namespace_id, "Test Namespace".to_string(), owner_id)
            .await
            .unwrap();

        assert_eq!(namespace.namespace_id, namespace_id);
        assert_eq!(namespace.name, "Test Namespace");
        assert_eq!(namespace.owner_identity_id, owner_id);
        assert!(namespace.active);
    }

    #[tokio::test]
    async fn test_create_namespace_duplicate_fails() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        service
            .create_namespace_internal(namespace_id, "Namespace 1".to_string(), owner_id)
            .await
            .unwrap();

        let result = service
            .create_namespace_internal(namespace_id, "Namespace 2".to_string(), owner_id)
            .await;

        assert!(matches!(
            result,
            Err(IdentityCoreError::NamespaceAlreadyExists(_))
        ));
    }

    #[tokio::test]
    async fn test_list_namespaces_returns_all_memberships() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;

        // The personal namespace should be queryable by ID
        let personal_ns = service.get_namespace_internal(owner_id).await.unwrap();
        assert_eq!(personal_ns.namespace_id, owner_id);

        // Create two additional namespaces
        let ns1 = Uuid::new_v4();
        let ns2 = Uuid::new_v4();
        let created_ns1 = service
            .create_namespace_internal(ns1, "NS1".to_string(), owner_id)
            .await
            .unwrap();
        assert_eq!(created_ns1.namespace_id, ns1);

        let created_ns2 = service
            .create_namespace_internal(ns2, "NS2".to_string(), owner_id)
            .await
            .unwrap();
        assert_eq!(created_ns2.namespace_id, ns2);

        // Verify we can get each namespace individually
        let fetched_ns1 = service.get_namespace_internal(ns1).await.unwrap();
        assert_eq!(fetched_ns1.name, "NS1");

        // Directly verify the index was written by checking with exact key
        let index_key = (owner_id, ns1);
        let index_exists: Option<()> = service
            .storage
            .get(CF_NAMESPACES_BY_IDENTITY, &index_key)
            .await
            .unwrap();
        assert!(
            index_exists.is_some(),
            "Index entry for ns1 should exist"
        );

        let namespaces = service.list_namespaces_internal(owner_id).await.unwrap();

        // Should have personal namespace + 2 created
        assert_eq!(namespaces.len(), 3);
    }

    #[tokio::test]
    async fn test_update_namespace_as_owner_success() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        service
            .create_namespace_internal(namespace_id, "Old Name".to_string(), owner_id)
            .await
            .unwrap();

        let updated = service
            .update_namespace_internal(namespace_id, "New Name".to_string(), owner_id)
            .await
            .unwrap();

        assert_eq!(updated.name, "New Name");
    }

    #[tokio::test]
    async fn test_update_namespace_as_non_owner_fails() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;
        let member_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        service
            .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
            .await
            .unwrap();

        // Add member as Admin
        service
            .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Admin, owner_id)
            .await
            .unwrap();

        // Admin tries to update namespace
        let result = service
            .update_namespace_internal(namespace_id, "New Name".to_string(), member_id)
            .await;

        assert!(matches!(
            result,
            Err(IdentityCoreError::InsufficientPermissions { .. })
        ));
    }

    #[tokio::test]
    async fn test_deactivate_namespace_success() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        service
            .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
            .await
            .unwrap();

        service
            .deactivate_namespace_internal(namespace_id, owner_id)
            .await
            .unwrap();

        let namespace = service.get_namespace_internal(namespace_id).await.unwrap();
        assert!(!namespace.active);
    }

    #[tokio::test]
    async fn test_reactivate_namespace_success() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        service
            .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
            .await
            .unwrap();
        service
            .deactivate_namespace_internal(namespace_id, owner_id)
            .await
            .unwrap();

        service
            .reactivate_namespace_internal(namespace_id, owner_id)
            .await
            .unwrap();

        let namespace = service.get_namespace_internal(namespace_id).await.unwrap();
        assert!(namespace.active);
    }

    #[tokio::test]
    async fn test_delete_namespace_empty_success() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        service
            .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
            .await
            .unwrap();

        service
            .delete_namespace_internal(namespace_id, owner_id)
            .await
            .unwrap();

        let result = service.get_namespace_internal(namespace_id).await;
        assert!(matches!(
            result,
            Err(IdentityCoreError::NamespaceNotFound(_))
        ));
    }

    #[tokio::test]
    async fn test_delete_namespace_with_members_fails() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;
        let member_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        service
            .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
            .await
            .unwrap();

        service
            .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Member, owner_id)
            .await
            .unwrap();

        let result = service
            .delete_namespace_internal(namespace_id, owner_id)
            .await;

        assert!(matches!(
            result,
            Err(IdentityCoreError::NamespaceHasMembers(_))
        ));
    }

    // ========================================================================
    // Membership Management Tests
    // ========================================================================

    #[tokio::test]
    async fn test_add_member_as_owner_success() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;
        let member_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        service
            .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
            .await
            .unwrap();

        let membership = service
            .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Member, owner_id)
            .await
            .unwrap();

        assert_eq!(membership.identity_id, member_id);
        assert_eq!(membership.namespace_id, namespace_id);
        assert_eq!(membership.role, NamespaceRole::Member);
    }

    #[tokio::test]
    async fn test_add_member_as_admin_success() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;
        let admin_id = create_test_identity(&service).await;
        let member_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        service
            .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
            .await
            .unwrap();

        // Add admin
        service
            .add_namespace_member_internal(namespace_id, admin_id, NamespaceRole::Admin, owner_id)
            .await
            .unwrap();

        // Admin adds member
        let membership = service
            .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Member, admin_id)
            .await
            .unwrap();

        assert_eq!(membership.role, NamespaceRole::Member);
    }

    #[tokio::test]
    async fn test_add_member_as_member_fails() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;
        let member1_id = create_test_identity(&service).await;
        let member2_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        service
            .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
            .await
            .unwrap();

        service
            .add_namespace_member_internal(namespace_id, member1_id, NamespaceRole::Member, owner_id)
            .await
            .unwrap();

        // Member tries to add another member
        let result = service
            .add_namespace_member_internal(namespace_id, member2_id, NamespaceRole::Member, member1_id)
            .await;

        assert!(matches!(
            result,
            Err(IdentityCoreError::InsufficientPermissions { .. })
        ));
    }

    #[tokio::test]
    async fn test_add_member_already_exists_fails() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;
        let member_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        service
            .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
            .await
            .unwrap();

        service
            .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Member, owner_id)
            .await
            .unwrap();

        let result = service
            .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Admin, owner_id)
            .await;

        assert!(matches!(
            result,
            Err(IdentityCoreError::MemberAlreadyExists { .. })
        ));
    }

    #[tokio::test]
    async fn test_update_member_role_success() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;
        let member_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        service
            .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
            .await
            .unwrap();

        service
            .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Member, owner_id)
            .await
            .unwrap();

        let updated = service
            .update_namespace_member_internal(namespace_id, member_id, NamespaceRole::Admin, owner_id)
            .await
            .unwrap();

        assert_eq!(updated.role, NamespaceRole::Admin);
    }

    #[tokio::test]
    async fn test_update_member_cannot_demote_owner() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        service
            .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
            .await
            .unwrap();

        let result = service
            .update_namespace_member_internal(namespace_id, owner_id, NamespaceRole::Admin, owner_id)
            .await;

        assert!(matches!(result, Err(IdentityCoreError::CannotRemoveOwner)));
    }

    #[tokio::test]
    async fn test_remove_member_success() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;
        let member_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        service
            .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
            .await
            .unwrap();

        service
            .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Member, owner_id)
            .await
            .unwrap();

        service
            .remove_namespace_member_internal(namespace_id, member_id, owner_id)
            .await
            .unwrap();

        let membership = service
            .get_namespace_membership_internal(member_id, namespace_id)
            .await
            .unwrap();
        assert!(membership.is_none());
    }

    #[tokio::test]
    async fn test_remove_owner_fails() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        service
            .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
            .await
            .unwrap();

        let result = service
            .remove_namespace_member_internal(namespace_id, owner_id, owner_id)
            .await;

        assert!(matches!(result, Err(IdentityCoreError::CannotRemoveOwner)));
    }

    #[tokio::test]
    async fn test_admin_cannot_remove_admin() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;
        let admin1_id = create_test_identity(&service).await;
        let admin2_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        service
            .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
            .await
            .unwrap();

        service
            .add_namespace_member_internal(namespace_id, admin1_id, NamespaceRole::Admin, owner_id)
            .await
            .unwrap();
        service
            .add_namespace_member_internal(namespace_id, admin2_id, NamespaceRole::Admin, owner_id)
            .await
            .unwrap();

        let result = service
            .remove_namespace_member_internal(namespace_id, admin2_id, admin1_id)
            .await;

        assert!(matches!(
            result,
            Err(IdentityCoreError::InsufficientPermissions { .. })
        ));
    }

    #[tokio::test]
    async fn test_member_can_self_remove() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;
        let member_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        service
            .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
            .await
            .unwrap();

        service
            .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Member, owner_id)
            .await
            .unwrap();

        // Member removes themselves
        service
            .remove_namespace_member_internal(namespace_id, member_id, member_id)
            .await
            .unwrap();

        let membership = service
            .get_namespace_membership_internal(member_id, namespace_id)
            .await
            .unwrap();
        assert!(membership.is_none());
    }

    #[tokio::test]
    async fn test_operations_on_inactive_namespace_fail() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;
        let member_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        service
            .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
            .await
            .unwrap();
        service
            .deactivate_namespace_internal(namespace_id, owner_id)
            .await
            .unwrap();

        // Try to add member to inactive namespace
        let result = service
            .add_namespace_member_internal(namespace_id, member_id, NamespaceRole::Member, owner_id)
            .await;

        assert!(matches!(
            result,
            Err(IdentityCoreError::NamespaceNotActive(_))
        ));
    }

    #[tokio::test]
    async fn test_admin_cannot_add_admin() {
        let service = create_test_service();
        let owner_id = create_test_identity(&service).await;
        let admin_id = create_test_identity(&service).await;
        let new_admin_id = create_test_identity(&service).await;

        let namespace_id = Uuid::new_v4();
        service
            .create_namespace_internal(namespace_id, "Test".to_string(), owner_id)
            .await
            .unwrap();

        service
            .add_namespace_member_internal(namespace_id, admin_id, NamespaceRole::Admin, owner_id)
            .await
            .unwrap();

        // Admin tries to add another admin
        let result = service
            .add_namespace_member_internal(namespace_id, new_admin_id, NamespaceRole::Admin, admin_id)
            .await;

        assert!(matches!(
            result,
            Err(IdentityCoreError::InsufficientPermissions { .. })
        ));
    }
}
