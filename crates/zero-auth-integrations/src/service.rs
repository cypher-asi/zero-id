//! Integrations service implementation.

use crate::traits::Integrations;
use crate::types::*;
use crate::webhook::{deliver_webhook, calculate_retry_delay, should_abandon_webhook};
use crate::{Error, Result};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_stream::Stream;
use uuid::Uuid;
use zero_auth_storage::{Storage, column_families::*};

/// Event sequence tracking per namespace
type SequenceMap = Arc<RwLock<std::collections::HashMap<Uuid, u64>>>;

/// SSE stream sender
type SseStream = tokio::sync::mpsc::Sender<RevocationEvent>;

/// Integrations service implementation
pub struct IntegrationsService<S: Storage> {
    storage: Arc<S>,
    sequences: SequenceMap,
    sse_streams: Arc<RwLock<std::collections::HashMap<Uuid, Vec<SseStream>>>>,
}

impl<S: Storage + 'static> IntegrationsService<S> {
    /// Create new integrations service
    pub fn new(storage: Arc<S>) -> Self {
        Self {
            storage,
            sequences: Arc::new(RwLock::new(std::collections::HashMap::new())),
            sse_streams: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Get current timestamp (Unix seconds)
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Generate next sequence number for namespace
    async fn next_sequence(&self, namespace_id: Uuid) -> Result<u64> {
        let mut sequences = self.sequences.write().await;
        let sequence = sequences.entry(namespace_id).or_insert(0);
        *sequence += 1;
        Ok(*sequence)
    }

    /// Broadcast event to SSE streams
    async fn broadcast_to_sse_streams(&self, event: &RevocationEvent) {
        let streams = self.sse_streams.read().await;
        
        // Find all services that should receive this event
        for (service_id, senders) in streams.iter() {
            // Get service to check filters
            let service = match self.get_service(*service_id).await {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Check if event should be delivered
            if !should_deliver_event(&service, event) {
                continue;
            }

            // Check scope
            if !has_event_scope(&service, event.event_type) {
                continue;
            }

            // Send to all active streams for this service
            for sender in senders {
                let _ = sender.try_send(event.clone());
            }
        }
    }

    /// Queue webhook delivery
    async fn queue_webhook_delivery(&self, event: &RevocationEvent) -> Result<()> {
        // Get all services that should receive webhooks
        let services = self.list_all_services().await?;

        for service in services {
            // Check if service has webhook configured
            let webhook_config = match &service.webhook_config {
                Some(config) if config.enabled => config,
                _ => continue,
            };

            // Check filters
            if !should_deliver_event(&service, event) {
                continue;
            }

            // Check scope
            if !has_event_scope(&service, event.event_type) {
                continue;
            }

            // Create delivery log entry
            let delivery_log = WebhookDeliveryLog {
                delivery_id: Uuid::new_v4(),
                service_id: service.service_id,
                event_id: event.event_id,
                attempt: 0,
                status: DeliveryStatus::Queued,
                attempted_at: Self::current_timestamp(),
                next_attempt_at: Some(Self::current_timestamp()),
                abandoned_at: None,
                http_status: None,
                error_message: None,
            };

            // Store delivery log
            let key = (service.service_id, event.event_id);
            self.storage.put(CF_WEBHOOK_DELIVERY_LOG, &key, &delivery_log).await?;

            // Spawn delivery task
            self.spawn_webhook_delivery(service.service_id, event.clone(), webhook_config.clone()).await;
        }

        Ok(())
    }

    /// Spawn webhook delivery task
    async fn spawn_webhook_delivery(&self, service_id: Uuid, event: RevocationEvent, webhook_config: WebhookConfig) {
        let storage = self.storage.clone();
        
        tokio::spawn(async move {
            let mut attempt = 1;
            let first_attempt_at = Self::current_timestamp();

            loop {
                let current_time = Self::current_timestamp();

                // Check if should abandon
                if should_abandon_webhook(attempt, first_attempt_at, current_time) {
                    let _ = Self::mark_webhook_abandoned(&storage, service_id, event.event_id).await;
                    break;
                }

                // Attempt delivery
                match deliver_webhook(&event, &webhook_config).await {
                    Ok(DeliveryStatus::Success) => {
                        // Success - update log and exit
                        let _ = Self::mark_webhook_success(&storage, service_id, event.event_id, attempt).await;
                        break;
                    }
                    Ok(DeliveryStatus::ClientError) => {
                        // Client error (4xx) - don't retry
                        let _ = Self::mark_webhook_client_error(&storage, service_id, event.event_id, attempt).await;
                        break;
                    }
                    Ok(DeliveryStatus::ServerError) | Err(_) => {
                        // Server error (5xx) or network error - retry
                        let delay = calculate_retry_delay(attempt);
                        let next_attempt_at = current_time + delay;
                        
                        let _ = Self::mark_webhook_retry(&storage, service_id, event.event_id, attempt, next_attempt_at).await;
                        
                        // Wait for retry delay
                        tokio::time::sleep(tokio::time::Duration::from_secs(delay)).await;
                        attempt += 1;
                    }
                    _ => break,
                }
            }
        });
    }

    /// Mark webhook as successful
    async fn mark_webhook_success(storage: &Arc<S>, service_id: Uuid, event_id: Uuid, attempt: u32) -> Result<()> {
        let key = (service_id, event_id);
        let mut log: WebhookDeliveryLog = storage.get(CF_WEBHOOK_DELIVERY_LOG, &key).await?
            .ok_or(Error::Other("Delivery log not found".to_string()))?;
        
        log.status = DeliveryStatus::Success;
        log.attempt = attempt;
        log.attempted_at = Self::current_timestamp();
        log.next_attempt_at = None;
        
        storage.put(CF_WEBHOOK_DELIVERY_LOG, &key, &log).await?;
        Ok(())
    }

    /// Mark webhook as client error (4xx)
    async fn mark_webhook_client_error(storage: &Arc<S>, service_id: Uuid, event_id: Uuid, attempt: u32) -> Result<()> {
        let key = (service_id, event_id);
        let mut log: WebhookDeliveryLog = storage.get(CF_WEBHOOK_DELIVERY_LOG, &key).await?
            .ok_or(Error::Other("Delivery log not found".to_string()))?;
        
        log.status = DeliveryStatus::ClientError;
        log.attempt = attempt;
        log.attempted_at = Self::current_timestamp();
        log.next_attempt_at = None;
        
        storage.put(CF_WEBHOOK_DELIVERY_LOG, &key, &log).await?;
        Ok(())
    }

    /// Mark webhook for retry
    async fn mark_webhook_retry(storage: &Arc<S>, service_id: Uuid, event_id: Uuid, attempt: u32, next_attempt_at: u64) -> Result<()> {
        let key = (service_id, event_id);
        let mut log: WebhookDeliveryLog = storage.get(CF_WEBHOOK_DELIVERY_LOG, &key).await?
            .ok_or(Error::Other("Delivery log not found".to_string()))?;
        
        log.status = DeliveryStatus::Retrying;
        log.attempt = attempt;
        log.attempted_at = Self::current_timestamp();
        log.next_attempt_at = Some(next_attempt_at);
        
        storage.put(CF_WEBHOOK_DELIVERY_LOG, &key, &log).await?;
        Ok(())
    }

    /// Mark webhook as abandoned
    async fn mark_webhook_abandoned(storage: &Arc<S>, service_id: Uuid, event_id: Uuid) -> Result<()> {
        let key = (service_id, event_id);
        let mut log: WebhookDeliveryLog = storage.get(CF_WEBHOOK_DELIVERY_LOG, &key).await?
            .ok_or(Error::Other("Delivery log not found".to_string()))?;
        
        log.status = DeliveryStatus::Abandoned;
        log.abandoned_at = Some(Self::current_timestamp());
        log.next_attempt_at = None;
        
        storage.put(CF_WEBHOOK_DELIVERY_LOG, &key, &log).await?;
        Ok(())
    }

    /// List all services (internal)
    async fn list_all_services(&self) -> Result<Vec<IntegrationService>> {
        // Note: In production, would implement scan_prefix on Storage trait
        // For now, we'll return empty list (webhook delivery would need to be improved)
        Ok(vec![])
    }

    /// Register SSE stream
    async fn register_sse_stream(&self, service_id: Uuid, sender: SseStream) {
        let mut streams = self.sse_streams.write().await;
        streams.entry(service_id).or_default().push(sender);
    }

    /// Unregister SSE stream
    #[allow(dead_code)]
    async fn unregister_sse_stream(&self, service_id: Uuid, sender_index: usize) {
        let mut streams = self.sse_streams.write().await;
        if let Some(senders) = streams.get_mut(&service_id) {
            if sender_index < senders.len() {
                senders.remove(sender_index);
            }
        }
    }

    /// Check if event has been processed by service (deduplication)
    pub async fn is_event_processed(&self, service_id: Uuid, event_id: Uuid) -> Result<bool> {
        let key = (service_id.as_bytes(), event_id.as_bytes());
        let key_bytes: Vec<u8> = key.0.iter().chain(key.1.iter()).copied().collect();
        
        let result: Option<u64> = self.storage
            .get(CF_PROCESSED_EVENT_IDS, &key_bytes)
            .await?;
        
        Ok(result.is_some())
    }

    /// Mark event as processed (deduplication)
    pub async fn mark_event_processed(&self, service_id: Uuid, event_id: Uuid) -> Result<()> {
        let key = (service_id.as_bytes(), event_id.as_bytes());
        let key_bytes: Vec<u8> = key.0.iter().chain(key.1.iter()).copied().collect();
        let value = Self::current_timestamp();
        
        // Store with 1-hour TTL (would need Storage trait support for TTL)
        self.storage.put(CF_PROCESSED_EVENT_IDS, &key_bytes, &value).await?;
        
        Ok(())
    }

    /// Clean up old webhook delivery logs
    ///
    /// Removes:
    /// - Abandoned webhooks older than 30 days
    /// - Successful deliveries older than 30 days
    pub async fn cleanup_old_webhooks(&self) -> Result<usize> {
        let _cutoff = Self::current_timestamp() - (30 * 24 * 3600);  // 30 days ago
        let deleted = 0;
        
        // Note: This is a placeholder implementation
        // In production, would need Storage trait support for prefix scanning
        // and would iterate through all webhook delivery logs
        
        Ok(deleted)
    }

    /// Get webhook queue size (for monitoring)
    ///
    /// Returns count of pending/retrying webhooks
    pub async fn get_webhook_queue_size(&self) -> Result<usize> {
        // Note: This is a placeholder implementation
        // In production, would need Storage trait support for prefix scanning
        // and would count webhooks with status Queued or Retrying
        
        Ok(0)
    }

    /// List all services (for admin operations)
    ///
    /// Note: This requires Storage trait support for prefix scanning
    pub async fn list_services(&self) -> Result<Vec<IntegrationService>> {
        // Note: This is a placeholder implementation
        // In production, would implement scan_prefix on Storage trait
        self.list_all_services().await
    }
}

impl<S: Storage + 'static> Integrations for IntegrationsService<S> {
    async fn authenticate_service(&self, client_cert: Certificate) -> Result<IntegrationService> {
        // Verify certificate validity
        let current_time = Self::current_timestamp();
        
        if client_cert.not_after < current_time {
            return Err(Error::CertificateExpired);
        }
        
        if client_cert.not_before > current_time {
            return Err(Error::CertificateValidationFailed(
                "Certificate not yet valid".to_string()
            ));
        }
        
        // Extract fingerprint
        let fingerprint = client_cert.fingerprint();
        
        // Lookup service by fingerprint
        let service_id_bytes: Option<[u8; 16]> = self.storage
            .get(CF_INTEGRATION_SERVICES_BY_CERT, &fingerprint)
            .await?;
        
        let service_id = service_id_bytes
            .map(Uuid::from_bytes)
            .ok_or(Error::UnknownService)?;
        
        // Get service
        let service: IntegrationService = self.storage
            .get(CF_INTEGRATION_SERVICES, &service_id.as_bytes())
            .await?
            .ok_or(Error::UnknownService)?;
        
        // Check revocation
        if service.revoked {
            return Err(Error::ServiceRevoked);
        }
        
        Ok(service)
    }

    async fn register_service(&self, request: RegisterServiceRequest) -> Result<Uuid> {
        // Validate request
        if request.service_name.len() > 128 {
            return Err(Error::ServiceNameTooLong);
        }
        
        if request.namespace_filter.len() > 100 {
            return Err(Error::TooManyNamespaces);
        }
        
        // Validate webhook URL if provided
        if let Some(webhook_config) = &request.webhook_config {
            if !webhook_config.url.starts_with("https://") {
                return Err(Error::InvalidWebhookUrl(
                    "Webhook URL must use HTTPS".to_string()
                ));
            }
        }
        
        // Check if certificate already registered
        let existing: Option<[u8; 16]> = self.storage
            .get(CF_INTEGRATION_SERVICES_BY_CERT, &request.client_cert_fingerprint)
            .await?;
        
        if existing.is_some() {
            return Err(Error::ServiceAlreadyRegistered);
        }
        
        // Create service
        let service_id = Uuid::new_v4();
        let service = IntegrationService {
            service_id,
            service_name: request.service_name,
            client_cert_fingerprint: request.client_cert_fingerprint,
            namespace_filter: request.namespace_filter,
            scopes: request.scopes,
            webhook_config: request.webhook_config,
            created_at: Self::current_timestamp(),
            last_used_at: None,
            revoked: false,
            revoked_at: None,
        };
        
        // Store service
        self.storage.put(CF_INTEGRATION_SERVICES, &service_id.as_bytes(), &service).await?;
        
        // Store cert-to-service mapping
        self.storage.put(
            CF_INTEGRATION_SERVICES_BY_CERT,
            &request.client_cert_fingerprint,
            &service_id.as_bytes()
        ).await?;
        
        Ok(service_id)
    }

    async fn revoke_service(&self, service_id: Uuid) -> Result<()> {
        // Get service
        let mut service: IntegrationService = self.storage
            .get(CF_INTEGRATION_SERVICES, &service_id.as_bytes())
            .await?
            .ok_or(Error::UnknownService)?;
        
        // Mark as revoked
        service.revoked = true;
        service.revoked_at = Some(Self::current_timestamp());
        
        // Update service
        self.storage.put(CF_INTEGRATION_SERVICES, &service_id.as_bytes(), &service).await?;
        
        Ok(())
    }

    async fn publish_event(&self, mut event: RevocationEvent) -> Result<()> {
        // Assign sequence number
        let sequence = self.next_sequence(event.namespace_id).await?;
        event.sequence = sequence;
        
        // Assign event ID if not set
        if event.event_id.is_nil() {
            event.event_id = Uuid::new_v4();
        }
        
        // Set timestamp if not set
        if event.timestamp == 0 {
            event.timestamp = Self::current_timestamp();
        }
        
        // Store event
        let key = (event.namespace_id.as_bytes(), sequence.to_be_bytes());
        let key_bytes: Vec<u8> = key.0.iter().chain(key.1.iter()).copied().collect();
        self.storage.put(CF_REVOCATION_EVENTS, &key_bytes, &event).await?;
        
        // Broadcast to SSE streams
        self.broadcast_to_sse_streams(&event).await;
        
        // Queue for webhook delivery
        self.queue_webhook_delivery(&event).await?;
        
        Ok(())
    }

    async fn stream_events(
        &self,
        service_id: Uuid,
        _last_sequence: u64,
    ) -> Result<impl Stream<Item = RevocationEvent> + Send> {
        // Get service
        let _service = self.get_service(service_id).await?;
        
        // Create channel for events
        let (tx, rx) = tokio::sync::mpsc::channel(100);
        
        // Register for live events (no backfill for now)
        // TODO: Implement event backfill when Storage trait supports range scans
        self.register_sse_stream(service_id, tx).await;
        
        // Return stream
        Ok(tokio_stream::wrappers::ReceiverStream::new(rx))
    }

    async fn update_webhook_config(
        &self,
        service_id: Uuid,
        webhook_config: Option<WebhookConfig>,
    ) -> Result<()> {
        // Get service
        let mut service: IntegrationService = self.storage
            .get(CF_INTEGRATION_SERVICES, &service_id.as_bytes())
            .await?
            .ok_or(Error::UnknownService)?;
        
        // Validate webhook URL if provided
        if let Some(config) = &webhook_config {
            if !config.url.starts_with("https://") {
                return Err(Error::InvalidWebhookUrl(
                    "Webhook URL must use HTTPS".to_string()
                ));
            }
        }
        
        // Update webhook config
        service.webhook_config = webhook_config;
        
        // Store service
        self.storage.put(CF_INTEGRATION_SERVICES, &service_id.as_bytes(), &service).await?;
        
        Ok(())
    }

    async fn get_service(&self, service_id: Uuid) -> Result<IntegrationService> {
        self.storage
            .get(CF_INTEGRATION_SERVICES, &service_id.as_bytes())
            .await?
            .ok_or(Error::UnknownService)
    }
}

/// Check if event should be delivered to service (namespace filtering)
pub fn should_deliver_event(service: &IntegrationService, event: &RevocationEvent) -> bool {
    // Empty namespace_filter = all namespaces
    if service.namespace_filter.is_empty() {
        return true;
    }
    
    // Check if event's namespace is in filter
    service.namespace_filter.contains(&event.namespace_id)
}

/// Check if service has scope for event type
pub fn has_event_scope(service: &IntegrationService, event_type: EventType) -> bool {
    match event_type {
        EventType::MachineRevoked => {
            service.scopes.contains(&Scope::EventsMachineRevoked)
        }
        EventType::SessionRevoked => {
            service.scopes.contains(&Scope::EventsSessionRevoked)
        }
        EventType::IdentityFrozen | EventType::IdentityDisabled => {
            service.scopes.contains(&Scope::EventsIdentityFrozen)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_auth_storage::RocksDbStorage;
    use tempfile::TempDir;

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
            Err(Error::ServiceAlreadyRegistered) => (),  // Expected
            Ok(id) => panic!("Expected ServiceAlreadyRegistered error, but got success with ID: {}", id),
            Err(e) => panic!("Expected ServiceAlreadyRegistered error, but got different error: {:?}", e),
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
            not_after: IntegrationsService::<RocksDbStorage>::current_timestamp() + 3600,
            not_before: IntegrationsService::<RocksDbStorage>::current_timestamp() - 3600,
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
            sequence: 0, // Will be assigned
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
        let is_processed = service.is_event_processed(service_id, event_id).await.unwrap();
        assert!(!is_processed);
        
        // Mark event as processed
        service.mark_event_processed(service_id, event_id).await.unwrap();
        
        // Event should now be processed
        let is_processed = service.is_event_processed(service_id, event_id).await.unwrap();
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
        
        service.update_webhook_config(service_id, Some(webhook_config.clone())).await.unwrap();
        
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
        
        let result = service.update_webhook_config(service_id, Some(webhook_config)).await;
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
}
