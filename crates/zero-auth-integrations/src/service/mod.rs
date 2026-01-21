//! Integrations service implementation.

mod sse;
mod webhooks;

use crate::traits::Integrations;
use crate::types::*;
use crate::{Error, Result};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_stream::Stream;
use uuid::Uuid;
use zero_auth_crypto::current_timestamp;
use zero_auth_storage::{column_families::*, Storage};

/// Event sequence tracking per namespace
type SequenceMap = Arc<RwLock<std::collections::HashMap<Uuid, u64>>>;

/// SSE stream sender
pub(crate) type SseStream = tokio::sync::mpsc::Sender<RevocationEvent>;

/// Integrations service implementation
pub struct IntegrationsService<S: Storage> {
    pub(crate) storage: Arc<S>,
    pub(crate) sequences: SequenceMap,
    pub(crate) sse_streams: Arc<RwLock<std::collections::HashMap<Uuid, Vec<SseStream>>>>,
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

    /// Generate next sequence number for namespace
    pub(crate) async fn next_sequence(&self, namespace_id: Uuid) -> Result<u64> {
        let mut sequences = self.sequences.write().await;
        let sequence = sequences.entry(namespace_id).or_insert(0);
        *sequence += 1;
        Ok(*sequence)
    }

    /// List all services (internal)
    pub(crate) async fn list_all_services(&self) -> Result<Vec<IntegrationService>> {
        // Note: In production, would implement scan_prefix on Storage trait
        // For now, we'll return empty list (webhook delivery would need to be improved)
        Ok(vec![])
    }

    /// Check if event has been processed by service (deduplication)
    pub async fn is_event_processed(&self, service_id: Uuid, event_id: Uuid) -> Result<bool> {
        let key = (service_id.as_bytes(), event_id.as_bytes());
        let key_bytes: Vec<u8> = key.0.iter().chain(key.1.iter()).copied().collect();

        let result: Option<u64> = self.storage.get(CF_PROCESSED_EVENT_IDS, &key_bytes).await?;

        Ok(result.is_some())
    }

    /// Mark event as processed (deduplication)
    pub async fn mark_event_processed(&self, service_id: Uuid, event_id: Uuid) -> Result<()> {
        let key = (service_id.as_bytes(), event_id.as_bytes());
        let key_bytes: Vec<u8> = key.0.iter().chain(key.1.iter()).copied().collect();
        let value = current_timestamp();

        // Store with 1-hour TTL (would need Storage trait support for TTL)
        self.storage
            .put(CF_PROCESSED_EVENT_IDS, &key_bytes, &value)
            .await?;

        Ok(())
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
        let current_time = current_timestamp();

        if client_cert.not_after < current_time {
            return Err(Error::CertificateExpired);
        }

        if client_cert.not_before > current_time {
            return Err(Error::CertificateValidationFailed(
                "Certificate not yet valid".to_string(),
            ));
        }

        // Extract fingerprint
        let fingerprint = client_cert.fingerprint();

        // Lookup service by fingerprint
        let service_id_bytes: Option<[u8; 16]> = self
            .storage
            .get(CF_INTEGRATION_SERVICES_BY_CERT, &fingerprint)
            .await?;

        let service_id = service_id_bytes
            .map(Uuid::from_bytes)
            .ok_or(Error::UnknownService)?;

        // Get service
        let service: IntegrationService = self
            .storage
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
                    "Webhook URL must use HTTPS".to_string(),
                ));
            }
        }

        // Check if certificate already registered
        let existing: Option<[u8; 16]> = self
            .storage
            .get(
                CF_INTEGRATION_SERVICES_BY_CERT,
                &request.client_cert_fingerprint,
            )
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
            created_at: current_timestamp(),
            last_used_at: None,
            revoked: false,
            revoked_at: None,
        };

        // Store service
        self.storage
            .put(CF_INTEGRATION_SERVICES, &service_id.as_bytes(), &service)
            .await?;

        // Store cert-to-service mapping
        self.storage
            .put(
                CF_INTEGRATION_SERVICES_BY_CERT,
                &request.client_cert_fingerprint,
                &service_id.as_bytes(),
            )
            .await?;

        Ok(service_id)
    }

    async fn revoke_service(&self, service_id: Uuid) -> Result<()> {
        // Get service
        let mut service: IntegrationService = self
            .storage
            .get(CF_INTEGRATION_SERVICES, &service_id.as_bytes())
            .await?
            .ok_or(Error::UnknownService)?;

        // Mark as revoked
        service.revoked = true;
        service.revoked_at = Some(current_timestamp());

        // Update service
        self.storage
            .put(CF_INTEGRATION_SERVICES, &service_id.as_bytes(), &service)
            .await?;

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
            event.timestamp = current_timestamp();
        }

        // Store event
        let key = (event.namespace_id.as_bytes(), sequence.to_be_bytes());
        let key_bytes: Vec<u8> = key.0.iter().chain(key.1.iter()).copied().collect();
        self.storage
            .put(CF_REVOCATION_EVENTS, &key_bytes, &event)
            .await?;

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
        let mut service: IntegrationService = self
            .storage
            .get(CF_INTEGRATION_SERVICES, &service_id.as_bytes())
            .await?
            .ok_or(Error::UnknownService)?;

        // Validate webhook URL if provided
        if let Some(config) = &webhook_config {
            if !config.url.starts_with("https://") {
                return Err(Error::InvalidWebhookUrl(
                    "Webhook URL must use HTTPS".to_string(),
                ));
            }
        }

        // Update webhook config
        service.webhook_config = webhook_config;

        // Store service
        self.storage
            .put(CF_INTEGRATION_SERVICES, &service_id.as_bytes(), &service)
            .await?;

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
        EventType::MachineRevoked => service.scopes.contains(&Scope::EventsMachineRevoked),
        EventType::SessionRevoked => service.scopes.contains(&Scope::EventsSessionRevoked),
        EventType::IdentityFrozen | EventType::IdentityDisabled => {
            service.scopes.contains(&Scope::EventsIdentityFrozen)
        }
    }
}

#[cfg(test)]
mod tests;
