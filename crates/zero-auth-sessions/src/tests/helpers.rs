//! Test helpers and mocks for session service tests.

use crate::*;
use async_trait::async_trait;
use std::sync::Arc;
use tempfile::TempDir;
use uuid::Uuid;
use zero_auth_identity_core::{IdentityCore, IdentityCoreService};
use zero_auth_policy::PolicyEngineImpl;
use zero_auth_storage::RocksDbStorage;

/// Mock event publisher for tests
pub struct MockIdentityCoreEventPublisher;

#[async_trait]
impl zero_auth_identity_core::EventPublisher for MockIdentityCoreEventPublisher {
    async fn publish(
        &self,
        _event: zero_auth_identity_core::RevocationEvent,
    ) -> zero_auth_identity_core::Result<()> {
        Ok(())
    }
}

pub type TestIdentityService =
    IdentityCoreService<PolicyEngineImpl<RocksDbStorage>, MockIdentityCoreEventPublisher, RocksDbStorage>;

/// Helper to create test storage
pub fn create_test_storage() -> (Arc<RocksDbStorage>, TempDir) {
    let temp_dir = tempfile::tempdir().unwrap();
    let db = RocksDbStorage::open(temp_dir.path()).unwrap();
    (Arc::new(db), temp_dir)
}

/// Helper to create test identity service
pub fn create_test_identity_service(storage: Arc<RocksDbStorage>) -> Arc<TestIdentityService> {
    let policy = Arc::new(PolicyEngineImpl::new(Arc::clone(&storage)));
    let event_publisher = Arc::new(MockIdentityCoreEventPublisher);
    Arc::new(IdentityCoreService::new(policy, event_publisher, storage))
}

/// Helper to create test session service
pub async fn create_test_session_service(
    storage: Arc<RocksDbStorage>,
    identity_core: Arc<TestIdentityService>,
) -> SessionService<RocksDbStorage, TestIdentityService, NoOpEventPublisher> {
    let service_master_key = [42u8; 32];
    let issuer = "zero-auth.test".to_string();
    let default_audience = vec!["zero-vault.test".to_string()];

    let service = SessionService::new(
        storage,
        identity_core,
        service_master_key,
        issuer,
        default_audience,
    );

    service.initialize().await.unwrap();
    service
}

/// Helper to create test identity with machine
pub async fn create_test_identity_with_machine(
    identity_core: &TestIdentityService,
) -> (Uuid, Uuid, Uuid) {
    use zero_auth_crypto::{canonicalize_identity_creation_message, sign_message, Ed25519KeyPair};
    use zero_auth_identity_core::{CreateIdentityRequest, MachineKey};

    let now = crate::current_timestamp();
    let identity_id = Uuid::new_v4();
    let machine_id = Uuid::new_v4();
    let namespace_id = Uuid::new_v4();

    // Create Ed25519 keypair for identity
    let identity_keypair = Ed25519KeyPair::from_seed(&[42u8; 32]).unwrap();
    let identity_signing_public_key = identity_keypair.public_key_bytes();

    let signing_public_key = [2u8; 32];
    let encryption_public_key = [3u8; 32];

    // Create machine key with full device capabilities for testing all operations
    let machine_key = MachineKey {
        machine_id,
        identity_id,
        namespace_id,
        signing_public_key,
        encryption_public_key,
        capabilities: zero_auth_crypto::MachineKeyCapabilities::FULL_DEVICE,
        epoch: 1,
        created_at: now,
        expires_at: None,
        last_used_at: None,
        device_name: "test-device".to_string(),
        device_platform: "test-platform".to_string(),
        revoked: false,
        revoked_at: None,
    };

    // Create canonical message
    let message = canonicalize_identity_creation_message(
        &identity_id,
        &identity_signing_public_key,
        &machine_id,
        &signing_public_key,
        &encryption_public_key,
        now,
    );

    // Sign the message
    let signature = sign_message(&identity_keypair, &message);

    // Create identity request
    let request = CreateIdentityRequest {
        identity_id,
        identity_signing_public_key,
        machine_key,
        authorization_signature: signature.to_vec(),
        namespace_name: Some("test-namespace".to_string()),
        created_at: now,
    };

    identity_core.create_identity(request).await.unwrap();

    (identity_id, machine_id, namespace_id)
}
