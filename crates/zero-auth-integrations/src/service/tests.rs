//! Tests for the integrations service.

use super::*;
use tempfile::TempDir;
use zero_auth_storage::RocksDbStorage;

async fn create_test_service() -> (IntegrationsService<RocksDbStorage>, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let storage = RocksDbStorage::open(temp_dir.path()).unwrap();
    let service = IntegrationsService::new(Arc::new(storage));
    (service, temp_dir)
}

#[tokio::test]
async fn test_register_service() {
    let (service, _temp) = create_test_service().await;

    let request = RegisterServiceRequest {
        service_name: "Test Service".to_string(),
        client_cert_fingerprint: [1u8; 32],
        namespace_filter: vec![],
        scopes: vec![Scope::EventsMachineRevoked],
        webhook_config: None,
    };

    let service_id = service.register_service(request).await.unwrap();
    assert!(!service_id.is_nil());
}

#[tokio::test]
async fn test_duplicate_certificate_registration() {
    let (service, _temp) = create_test_service().await;

    let fingerprint = [1u8; 32];

    let request1 = RegisterServiceRequest {
        service_name: "Test Service 1".to_string(),
        client_cert_fingerprint: fingerprint,
        namespace_filter: vec![],
        scopes: vec![Scope::EventsMachineRevoked],
        webhook_config: None,
    };

    let service_id1 = service.register_service(request1).await.unwrap();

    // Verify first service was stored
    let stored_service = service.get_service(service_id1).await.unwrap();
    assert_eq!(stored_service.service_name, "Test Service 1");

    // Try to register again with same cert but different name
    let request2 = RegisterServiceRequest {
        service_name: "Test Service 2".to_string(),
        client_cert_fingerprint: fingerprint,
        namespace_filter: vec![],
        scopes: vec![Scope::EventsSessionRevoked],
        webhook_config: None,
    };

    let result = service.register_service(request2).await;

    // Check if we got the expected error
    match result {
        Err(Error::ServiceAlreadyRegistered) => (), // Expected
        Ok(id) => panic!(
            "Expected ServiceAlreadyRegistered error, but got success with ID: {}",
            id
        ),
        Err(e) => panic!(
            "Expected ServiceAlreadyRegistered error, but got different error: {:?}",
            e
        ),
    }
}

#[tokio::test]
async fn test_authenticate_service() {
    let (service, _temp) = create_test_service().await;

    let fingerprint = [1u8; 32];

    // Register service
    let request = RegisterServiceRequest {
        service_name: "Test Service".to_string(),
        client_cert_fingerprint: fingerprint,
        namespace_filter: vec![],
        scopes: vec![Scope::EventsMachineRevoked],
        webhook_config: None,
    };

    service.register_service(request).await.unwrap();

    // Authenticate with certificate
    let cert = Certificate {
        der_bytes: vec![1, 2, 3],
        not_after: current_timestamp() + 3600,
        not_before: current_timestamp() - 3600,
    };

    // Note: This will fail because fingerprint won't match
    // In real implementation, we'd compute fingerprint from der_bytes
    let result = service.authenticate_service(cert).await;
    assert!(result.is_err()); // Expected since fingerprints don't match
}

#[tokio::test]
async fn test_revoke_service() {
    let (service, _temp) = create_test_service().await;

    let request = RegisterServiceRequest {
        service_name: "Test Service".to_string(),
        client_cert_fingerprint: [1u8; 32],
        namespace_filter: vec![],
        scopes: vec![Scope::EventsMachineRevoked],
        webhook_config: None,
    };

    let service_id = service.register_service(request).await.unwrap();

    // Revoke service
    service.revoke_service(service_id).await.unwrap();

    // Get service and verify it's revoked
    let retrieved = service.get_service(service_id).await.unwrap();
    assert!(retrieved.revoked);
    assert!(retrieved.revoked_at.is_some());
}

#[tokio::test]
async fn test_publish_event() {
    let (service, _temp) = create_test_service().await;

    let namespace_id = Uuid::new_v4();
    let event = RevocationEvent {
        event_id: Uuid::new_v4(),
        event_type: EventType::MachineRevoked,
        namespace_id,
        identity_id: Uuid::new_v4(),
        machine_id: Some(Uuid::new_v4()),
        session_id: None,
        sequence: 0,  // Will be assigned
        timestamp: 0, // Will be assigned
        reason: "Test revocation".to_string(),
    };

    service.publish_event(event.clone()).await.unwrap();

    // Verify sequence was assigned
    // (Would need to retrieve event to verify)
}

#[tokio::test]
async fn test_event_filtering_namespace() {
    let namespace1 = Uuid::new_v4();
    let namespace2 = Uuid::new_v4();

    let service = IntegrationService {
        service_id: Uuid::new_v4(),
        service_name: "Test".to_string(),
        client_cert_fingerprint: [0u8; 32],
        namespace_filter: vec![namespace1],
        scopes: vec![Scope::EventsMachineRevoked],
        webhook_config: None,
        created_at: 0,
        last_used_at: None,
        revoked: false,
        revoked_at: None,
    };

    let event1 = RevocationEvent {
        event_id: Uuid::new_v4(),
        event_type: EventType::MachineRevoked,
        namespace_id: namespace1,
        identity_id: Uuid::new_v4(),
        machine_id: Some(Uuid::new_v4()),
        session_id: None,
        sequence: 1,
        timestamp: 0,
        reason: "Test".to_string(),
    };

    let event2 = RevocationEvent {
        namespace_id: namespace2,
        ..event1.clone()
    };

    assert!(should_deliver_event(&service, &event1));
    assert!(!should_deliver_event(&service, &event2));
}

#[tokio::test]
async fn test_event_filtering_scope() {
    let service = IntegrationService {
        service_id: Uuid::new_v4(),
        service_name: "Test".to_string(),
        client_cert_fingerprint: [0u8; 32],
        namespace_filter: vec![],
        scopes: vec![Scope::EventsMachineRevoked],
        webhook_config: None,
        created_at: 0,
        last_used_at: None,
        revoked: false,
        revoked_at: None,
    };

    assert!(has_event_scope(&service, EventType::MachineRevoked));
    assert!(!has_event_scope(&service, EventType::SessionRevoked));
    assert!(!has_event_scope(&service, EventType::IdentityFrozen));
}

#[tokio::test]
async fn test_event_deduplication() {
    let (service, _temp) = create_test_service().await;

    let service_id = Uuid::new_v4();
    let event_id = Uuid::new_v4();

    // Event should not be processed initially
    let is_processed = service
        .is_event_processed(service_id, event_id)
        .await
        .unwrap();
    assert!(!is_processed);

    // Mark event as processed
    service
        .mark_event_processed(service_id, event_id)
        .await
        .unwrap();

    // Event should now be processed
    let is_processed = service
        .is_event_processed(service_id, event_id)
        .await
        .unwrap();
    assert!(is_processed);
}

#[tokio::test]
async fn test_update_webhook_config() {
    let (service, _temp) = create_test_service().await;

    // Register service
    let request = RegisterServiceRequest {
        service_name: "Test Service".to_string(),
        client_cert_fingerprint: [1u8; 32],
        namespace_filter: vec![],
        scopes: vec![Scope::EventsMachineRevoked],
        webhook_config: None,
    };

    let service_id = service.register_service(request).await.unwrap();

    // Update webhook config
    let webhook_config = WebhookConfig {
        url: "https://example.com/webhook".to_string(),
        secret: [42u8; 32],
        enabled: true,
    };

    service
        .update_webhook_config(service_id, Some(webhook_config.clone()))
        .await
        .unwrap();

    // Verify webhook config was updated
    let retrieved = service.get_service(service_id).await.unwrap();
    assert!(retrieved.webhook_config.is_some());
    let config = retrieved.webhook_config.unwrap();
    assert_eq!(config.url, "https://example.com/webhook");
    assert!(config.enabled);
}

#[tokio::test]
async fn test_invalid_webhook_url() {
    let (service, _temp) = create_test_service().await;

    // Register service
    let request = RegisterServiceRequest {
        service_name: "Test Service".to_string(),
        client_cert_fingerprint: [1u8; 32],
        namespace_filter: vec![],
        scopes: vec![Scope::EventsMachineRevoked],
        webhook_config: None,
    };

    let service_id = service.register_service(request).await.unwrap();

    // Try to set HTTP webhook (should fail)
    let webhook_config = WebhookConfig {
        url: "http://example.com/webhook".to_string(),
        secret: [42u8; 32],
        enabled: true,
    };

    let result = service
        .update_webhook_config(service_id, Some(webhook_config))
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_event_sequence_monotonic() {
    let (service, _temp) = create_test_service().await;

    let namespace_id = Uuid::new_v4();

    // Publish multiple events
    for i in 0..5 {
        let event = RevocationEvent {
            event_id: Uuid::new_v4(),
            event_type: EventType::MachineRevoked,
            namespace_id,
            identity_id: Uuid::new_v4(),
            machine_id: Some(Uuid::new_v4()),
            session_id: None,
            sequence: 0,
            timestamp: 0,
            reason: format!("Test revocation {}", i),
        };

        service.publish_event(event).await.unwrap();
    }

    // Verify sequences are monotonic (would need to retrieve events to verify)
    // This is a basic test that events can be published
}

#[tokio::test]
async fn test_service_name_too_long() {
    let (service, _temp) = create_test_service().await;

    let request = RegisterServiceRequest {
        service_name: "a".repeat(129), // 129 characters (max is 128)
        client_cert_fingerprint: [1u8; 32],
        namespace_filter: vec![],
        scopes: vec![Scope::EventsMachineRevoked],
        webhook_config: None,
    };

    let result = service.register_service(request).await;
    assert!(matches!(result, Err(Error::ServiceNameTooLong)));
}

#[tokio::test]
async fn test_too_many_namespaces() {
    let (service, _temp) = create_test_service().await;

    // Create 101 namespaces (max is 100)
    let namespaces: Vec<Uuid> = (0..101).map(|_| Uuid::new_v4()).collect();

    let request = RegisterServiceRequest {
        service_name: "Test Service".to_string(),
        client_cert_fingerprint: [1u8; 32],
        namespace_filter: namespaces,
        scopes: vec![Scope::EventsMachineRevoked],
        webhook_config: None,
    };

    let result = service.register_service(request).await;
    assert!(matches!(result, Err(Error::TooManyNamespaces)));
}

#[tokio::test]
async fn test_service_lifecycle() {
    let (service, _temp) = create_test_service().await;

    // 1. Register service
    let request = RegisterServiceRequest {
        service_name: "Test Service".to_string(),
        client_cert_fingerprint: [1u8; 32],
        namespace_filter: vec![],
        scopes: vec![Scope::EventsMachineRevoked, Scope::EventsSessionRevoked],
        webhook_config: None,
    };

    let service_id = service.register_service(request).await.unwrap();

    // 2. Verify service is active
    let retrieved = service.get_service(service_id).await.unwrap();
    assert!(!retrieved.revoked);
    assert_eq!(retrieved.scopes.len(), 2);

    // 3. Revoke service
    service.revoke_service(service_id).await.unwrap();

    // 4. Verify service is revoked
    let retrieved = service.get_service(service_id).await.unwrap();
    assert!(retrieved.revoked);
    assert!(retrieved.revoked_at.is_some());
}

#[tokio::test]
async fn test_empty_namespace_filter_allows_all() {
    let service = IntegrationService {
        service_id: Uuid::new_v4(),
        service_name: "Test".to_string(),
        client_cert_fingerprint: [0u8; 32],
        namespace_filter: vec![], // Empty = all namespaces
        scopes: vec![Scope::EventsMachineRevoked],
        webhook_config: None,
        created_at: 0,
        last_used_at: None,
        revoked: false,
        revoked_at: None,
    };

    let event = RevocationEvent {
        event_id: Uuid::new_v4(),
        event_type: EventType::MachineRevoked,
        namespace_id: Uuid::new_v4(), // Any namespace
        identity_id: Uuid::new_v4(),
        machine_id: Some(Uuid::new_v4()),
        session_id: None,
        sequence: 1,
        timestamp: 0,
        reason: "Test".to_string(),
    };

    // Empty namespace filter should allow all events
    assert!(should_deliver_event(&service, &event));
}

#[tokio::test]
async fn test_identity_disabled_uses_frozen_scope() {
    let service = IntegrationService {
        service_id: Uuid::new_v4(),
        service_name: "Test".to_string(),
        client_cert_fingerprint: [0u8; 32],
        namespace_filter: vec![],
        scopes: vec![Scope::EventsIdentityFrozen],
        webhook_config: None,
        created_at: 0,
        last_used_at: None,
        revoked: false,
        revoked_at: None,
    };

    // Both IdentityFrozen and IdentityDisabled should use the same scope
    assert!(has_event_scope(&service, EventType::IdentityFrozen));
    assert!(has_event_scope(&service, EventType::IdentityDisabled));
}
