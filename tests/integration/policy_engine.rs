//! Policy Engine Integration Tests
//!
//! End-to-end tests for policy enforcement scenarios including:
//! - Frozen identity blocks all operations
//! - Revoked machine key blocks authentication
//! - Insufficient capabilities blocks operations
//! - Rate limiting after repeated failures

use std::sync::Arc;
use uuid::Uuid;
use zero_auth_crypto::{
    canonicalize_identity_creation_message, derive_identity_signing_keypair, sign_message,
    MachineKeyCapabilities, NeuralKey,
};
use zero_auth_identity_core::{
    CreateIdentityRequest, IdentityCore, IdentityCoreService, IdentityStatus, MachineKey,
};
use zero_auth_policy::{
    capabilities, IdentityStatus as PolicyIdentityStatus, Operation, PolicyContext, PolicyEngine,
    PolicyEngineImpl, RateLimitConfig, Verdict,
};
use zero_auth_storage::RocksDbStorage;

/// Mock event publisher for tests
struct MockEventPublisher;

#[async_trait::async_trait]
impl zero_auth_identity_core::EventPublisher for MockEventPublisher {
    async fn publish(
        &self,
        _event: zero_auth_identity_core::RevocationEvent,
    ) -> zero_auth_identity_core::Result<()> {
        Ok(())
    }
}

type TestService =
    IdentityCoreService<PolicyEngineImpl<RocksDbStorage>, MockEventPublisher, RocksDbStorage>;

/// Helper to create test infrastructure
fn create_test_infrastructure() -> (Arc<RocksDbStorage>, Arc<PolicyEngineImpl<RocksDbStorage>>, TestService) {
    let storage = Arc::new(RocksDbStorage::open_test().unwrap());
    let policy = Arc::new(PolicyEngineImpl::new(Arc::clone(&storage)));
    let events = Arc::new(MockEventPublisher);
    let service = IdentityCoreService::new(Arc::clone(&policy), events, Arc::clone(&storage));
    (storage, policy, service)
}

/// Helper to create a test identity
async fn create_test_identity(service: &TestService) -> (Uuid, Uuid, NeuralKey) {
    let neural_key = NeuralKey::generate().unwrap();
    let identity_id = Uuid::new_v4();
    let machine_id = Uuid::new_v4();

    let (identity_signing_public_key, identity_keypair) =
        derive_identity_signing_keypair(&neural_key, &identity_id).unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let machine_key = MachineKey {
        machine_id,
        identity_id,
        namespace_id: identity_id,
        signing_public_key: [1u8; 32],
        encryption_public_key: [2u8; 32],
        capabilities: MachineKeyCapabilities::FULL_DEVICE,
        epoch: 0,
        created_at: now,
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
        now,
    );

    let signature = sign_message(&identity_keypair, &message);

    let request = CreateIdentityRequest {
        identity_id,
        identity_signing_public_key,
        machine_key,
        authorization_signature: signature.to_vec(),
        namespace_name: Some("test-namespace".to_string()),
        created_at: now,
    };

    service.create_identity(request).await.unwrap();
    (identity_id, machine_id, neural_key)
}

#[tokio::test]
async fn test_policy_blocks_frozen_identity() {
    let (_storage, policy, service) = create_test_infrastructure();
    let (identity_id, machine_id, _) = create_test_identity(&service).await;

    // Verify identity is active
    let identity = service.get_identity(identity_id).await.unwrap();
    assert_eq!(identity.status, IdentityStatus::Active);

    // Create policy context for a login attempt with frozen status
    let context = PolicyContext {
        identity_id,
        machine_id: Some(machine_id),
        namespace_id: identity_id,
        auth_method: zero_auth_policy::AuthMethod::MachineKey,
        mfa_verified: false,
        operation: Operation::Login,
        resource: None,
        ip_address: "127.0.0.1".to_string(),
        user_agent: "test".to_string(),
        timestamp: 0,
        reputation_score: 50,
        recent_failed_attempts: 0,
        identity_status: Some(PolicyIdentityStatus::Frozen),
        machine_revoked: Some(false),
        machine_capabilities: Some(capabilities::AUTHENTICATE),
        namespace_active: Some(true),
    };

    let decision = policy.evaluate(context).await.unwrap();
    assert_eq!(decision.verdict, Verdict::Deny);
    assert!(decision.reason.contains("frozen"));
}

#[tokio::test]
async fn test_policy_blocks_disabled_identity() {
    let (_storage, policy, _service) = create_test_infrastructure();

    let context = PolicyContext {
        identity_id: Uuid::new_v4(),
        machine_id: Some(Uuid::new_v4()),
        namespace_id: Uuid::new_v4(),
        auth_method: zero_auth_policy::AuthMethod::MachineKey,
        mfa_verified: false,
        operation: Operation::Login,
        resource: None,
        ip_address: "127.0.0.1".to_string(),
        user_agent: "test".to_string(),
        timestamp: 0,
        reputation_score: 50,
        recent_failed_attempts: 0,
        identity_status: Some(PolicyIdentityStatus::Disabled),
        machine_revoked: Some(false),
        machine_capabilities: Some(capabilities::AUTHENTICATE),
        namespace_active: Some(true),
    };

    let decision = policy.evaluate(context).await.unwrap();
    assert_eq!(decision.verdict, Verdict::Deny);
    assert!(decision.reason.contains("Disabled"));
}

#[tokio::test]
async fn test_policy_blocks_revoked_machine() {
    let (_storage, policy, _service) = create_test_infrastructure();

    let context = PolicyContext {
        identity_id: Uuid::new_v4(),
        machine_id: Some(Uuid::new_v4()),
        namespace_id: Uuid::new_v4(),
        auth_method: zero_auth_policy::AuthMethod::MachineKey,
        mfa_verified: false,
        operation: Operation::Login,
        resource: None,
        ip_address: "127.0.0.1".to_string(),
        user_agent: "test".to_string(),
        timestamp: 0,
        reputation_score: 50,
        recent_failed_attempts: 0,
        identity_status: Some(PolicyIdentityStatus::Active),
        machine_revoked: Some(true), // Machine is revoked
        machine_capabilities: Some(capabilities::AUTHENTICATE),
        namespace_active: Some(true),
    };

    let decision = policy.evaluate(context).await.unwrap();
    assert_eq!(decision.verdict, Verdict::Deny);
    assert!(decision.reason.contains("revoked"));
}

#[tokio::test]
async fn test_policy_blocks_insufficient_capabilities() {
    let (_storage, policy, _service) = create_test_infrastructure();

    // Try to enroll a machine with only AUTHENTICATE capability
    // (EnrollMachine requires AUTHENTICATE | SIGN | ENROLL)
    let context = PolicyContext {
        identity_id: Uuid::new_v4(),
        machine_id: Some(Uuid::new_v4()),
        namespace_id: Uuid::new_v4(),
        auth_method: zero_auth_policy::AuthMethod::MachineKey,
        mfa_verified: false,
        operation: Operation::EnrollMachine,
        resource: None,
        ip_address: "127.0.0.1".to_string(),
        user_agent: "test".to_string(),
        timestamp: 0,
        reputation_score: 50,
        recent_failed_attempts: 0,
        identity_status: Some(PolicyIdentityStatus::Active),
        machine_revoked: Some(false),
        machine_capabilities: Some(capabilities::AUTHENTICATE), // Missing SIGN and ENROLL
        namespace_active: Some(true),
    };

    let decision = policy.evaluate(context).await.unwrap();
    assert_eq!(decision.verdict, Verdict::Deny);
    assert!(decision.reason.contains("capabilities"));
}

#[tokio::test]
async fn test_policy_allows_sufficient_capabilities() {
    let (_storage, policy, _service) = create_test_infrastructure();

    // Try to enroll a machine with all required capabilities
    let context = PolicyContext {
        identity_id: Uuid::new_v4(),
        machine_id: Some(Uuid::new_v4()),
        namespace_id: Uuid::new_v4(),
        auth_method: zero_auth_policy::AuthMethod::MachineKey,
        mfa_verified: false,
        operation: Operation::EnrollMachine,
        resource: None,
        ip_address: "127.0.0.1".to_string(),
        user_agent: "test".to_string(),
        timestamp: 0,
        reputation_score: 50,
        recent_failed_attempts: 0,
        identity_status: Some(PolicyIdentityStatus::Active),
        machine_revoked: Some(false),
        machine_capabilities: Some(
            capabilities::AUTHENTICATE | capabilities::SIGN | capabilities::ENROLL,
        ),
        namespace_active: Some(true),
    };

    let decision = policy.evaluate(context).await.unwrap();
    assert_eq!(decision.verdict, Verdict::Allow);
}

#[tokio::test]
async fn test_policy_blocks_inactive_namespace() {
    let (_storage, policy, _service) = create_test_infrastructure();

    let context = PolicyContext {
        identity_id: Uuid::new_v4(),
        machine_id: Some(Uuid::new_v4()),
        namespace_id: Uuid::new_v4(),
        auth_method: zero_auth_policy::AuthMethod::MachineKey,
        mfa_verified: false,
        operation: Operation::Login,
        resource: None,
        ip_address: "127.0.0.1".to_string(),
        user_agent: "test".to_string(),
        timestamp: 0,
        reputation_score: 50,
        recent_failed_attempts: 0,
        identity_status: Some(PolicyIdentityStatus::Active),
        machine_revoked: Some(false),
        machine_capabilities: Some(capabilities::AUTHENTICATE),
        namespace_active: Some(false), // Namespace is inactive
    };

    let decision = policy.evaluate(context).await.unwrap();
    assert_eq!(decision.verdict, Verdict::Deny);
    assert!(decision.reason.contains("Namespace"));
}

#[tokio::test]
async fn test_rate_limit_after_failures() {
    let (_storage, policy, _service) = create_test_infrastructure();
    let identity_id = Uuid::new_v4();

    // Record multiple failed attempts
    for _ in 0..6 {
        policy
            .record_attempt(identity_id, Operation::Login, false)
            .await
            .unwrap();
    }

    // Create context with high failure count
    let context = PolicyContext {
        identity_id,
        machine_id: Some(Uuid::new_v4()),
        namespace_id: Uuid::new_v4(),
        auth_method: zero_auth_policy::AuthMethod::MachineKey,
        mfa_verified: false,
        operation: Operation::Login,
        resource: None,
        ip_address: "127.0.0.1".to_string(),
        user_agent: "test".to_string(),
        timestamp: 0,
        reputation_score: 50,
        recent_failed_attempts: 6, // Above threshold
        identity_status: Some(PolicyIdentityStatus::Active),
        machine_revoked: Some(false),
        machine_capabilities: Some(capabilities::AUTHENTICATE),
        namespace_active: Some(true),
    };

    let decision = policy.evaluate(context).await.unwrap();
    assert_eq!(decision.verdict, Verdict::RateLimited);
}

#[tokio::test]
async fn test_reputation_decreases_after_failures() {
    let (_storage, policy, _service) = create_test_infrastructure();
    let identity_id = Uuid::new_v4();

    // Initial reputation should be neutral (50)
    let initial_rep = policy.get_reputation(identity_id).await.unwrap();
    assert_eq!(initial_rep, 50);

    // Record some successful attempts
    for _ in 0..5 {
        policy
            .record_attempt(identity_id, Operation::Login, true)
            .await
            .unwrap();
    }

    let after_success = policy.get_reputation(identity_id).await.unwrap();
    assert!(after_success > initial_rep);

    // Record many failed attempts
    for _ in 0..10 {
        policy
            .record_attempt(identity_id, Operation::Login, false)
            .await
            .unwrap();
    }

    let after_failures = policy.get_reputation(identity_id).await.unwrap();
    assert!(after_failures < after_success);
}

#[tokio::test]
async fn test_configurable_rate_limits() {
    let storage = Arc::new(RocksDbStorage::open_test().unwrap());

    // Create engine with strict rate limits
    let config = RateLimitConfig {
        ip_window_seconds: 60,
        ip_max_requests: 3, // Very strict: only 3 requests
        identity_window_seconds: 3600,
        identity_max_requests: 100,
        failure_window_seconds: 900,
        failure_max_attempts: 2,
    };

    let policy = PolicyEngineImpl::with_config(storage, config);

    // Should allow first 3 requests
    assert!(policy.check_ip_rate_limit("192.168.1.1").is_some());
    assert!(policy.check_ip_rate_limit("192.168.1.1").is_some());
    assert!(policy.check_ip_rate_limit("192.168.1.1").is_some());

    // Fourth request should be blocked
    assert!(policy.check_ip_rate_limit("192.168.1.1").is_none());

    // Different IP should still be allowed
    assert!(policy.check_ip_rate_limit("192.168.1.2").is_some());
}

#[tokio::test]
async fn test_evaluation_priority_frozen_over_others() {
    let (_storage, policy, _service) = create_test_infrastructure();

    // Set multiple deny conditions, frozen should take priority
    let context = PolicyContext {
        identity_id: Uuid::new_v4(),
        machine_id: Some(Uuid::new_v4()),
        namespace_id: Uuid::new_v4(),
        auth_method: zero_auth_policy::AuthMethod::MachineKey,
        mfa_verified: false,
        operation: Operation::Login,
        resource: None,
        ip_address: "127.0.0.1".to_string(),
        user_agent: "test".to_string(),
        timestamp: 0,
        reputation_score: -100, // Would trigger reputation denial
        recent_failed_attempts: 100, // Would trigger rate limit
        identity_status: Some(PolicyIdentityStatus::Frozen), // Highest priority
        machine_revoked: Some(true), // Would trigger machine denial
        machine_capabilities: Some(0), // Would trigger capability denial
        namespace_active: Some(false), // Would trigger namespace denial
    };

    let decision = policy.evaluate(context).await.unwrap();
    assert_eq!(decision.verdict, Verdict::Deny);
    // Frozen should be the reason (highest priority check)
    assert!(decision.reason.contains("frozen"));
}

#[tokio::test]
async fn test_mfa_required_for_sensitive_operations() {
    let (_storage, policy, _service) = create_test_infrastructure();

    // ChangePassword requires MFA
    let context = PolicyContext {
        identity_id: Uuid::new_v4(),
        machine_id: Some(Uuid::new_v4()),
        namespace_id: Uuid::new_v4(),
        auth_method: zero_auth_policy::AuthMethod::MachineKey,
        mfa_verified: false, // MFA not verified
        operation: Operation::ChangePassword,
        resource: None,
        ip_address: "127.0.0.1".to_string(),
        user_agent: "test".to_string(),
        timestamp: 0,
        reputation_score: 50,
        recent_failed_attempts: 0,
        identity_status: Some(PolicyIdentityStatus::Active),
        machine_revoked: Some(false),
        machine_capabilities: Some(capabilities::AUTHENTICATE | capabilities::SIGN),
        namespace_active: Some(true),
    };

    let decision = policy.evaluate(context).await.unwrap();
    assert_eq!(decision.verdict, Verdict::RequireAdditionalAuth);
    assert!(decision.reason.contains("MFA"));
}

#[tokio::test]
async fn test_approvals_required_for_critical_operations() {
    let (_storage, policy, _service) = create_test_infrastructure();

    // UnfreezeIdentity requires 2 approvals
    let context = PolicyContext {
        identity_id: Uuid::new_v4(),
        machine_id: Some(Uuid::new_v4()),
        namespace_id: Uuid::new_v4(),
        auth_method: zero_auth_policy::AuthMethod::MachineKey,
        mfa_verified: true,
        operation: Operation::UnfreezeIdentity,
        resource: None,
        ip_address: "127.0.0.1".to_string(),
        user_agent: "test".to_string(),
        timestamp: 0,
        reputation_score: 50,
        recent_failed_attempts: 0,
        identity_status: Some(PolicyIdentityStatus::Active),
        machine_revoked: Some(false),
        machine_capabilities: Some(
            capabilities::AUTHENTICATE | capabilities::SIGN | capabilities::APPROVE,
        ),
        namespace_active: Some(true),
    };

    let decision = policy.evaluate(context).await.unwrap();
    assert_eq!(decision.verdict, Verdict::RequireApproval);
    assert_eq!(decision.required_approvals, 2);
}
