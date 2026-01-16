//! Trait definitions for integrations subsystem.

use crate::types::*;
use crate::Result;
use tokio_stream::Stream;
use uuid::Uuid;

/// Integrations & Events subsystem trait
pub trait Integrations: Send + Sync {
    /// Authenticate integration service with mTLS
    ///
    /// # Arguments
    /// * `client_cert` - Client certificate from mTLS handshake
    ///
    /// # Returns
    /// * Authenticated IntegrationService
    ///
    /// # Errors
    /// * `UnknownService` - Certificate fingerprint not registered
    /// * `ServiceRevoked` - Service has been revoked
    /// * `CertificateExpired` - Certificate is expired
    fn authenticate_service(
        &self,
        client_cert: Certificate,
    ) -> impl std::future::Future<Output = Result<IntegrationService>> + Send;

    /// Register new integration service
    ///
    /// # Arguments
    /// * `request` - Service registration request
    ///
    /// # Returns
    /// * Service ID
    ///
    /// # Errors
    /// * `ServiceAlreadyRegistered` - Certificate already registered
    /// * `InvalidNamespaceFilter` - Invalid namespace filter
    fn register_service(
        &self,
        request: RegisterServiceRequest,
    ) -> impl std::future::Future<Output = Result<Uuid>> + Send;

    /// Revoke integration service
    ///
    /// # Arguments
    /// * `service_id` - Service ID to revoke
    ///
    /// # Errors
    /// * `UnknownService` - Service not found
    fn revoke_service(
        &self,
        service_id: Uuid,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Publish revocation event
    ///
    /// # Arguments
    /// * `event` - Revocation event to publish
    ///
    /// # Errors
    /// * `SequenceGenerationFailed` - Failed to generate sequence number
    fn publish_event(
        &self,
        event: RevocationEvent,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Stream events via SSE (backfill + live)
    ///
    /// # Arguments
    /// * `service_id` - Service ID
    /// * `last_sequence` - Last sequence number seen (0 for all events)
    ///
    /// # Returns
    /// * Stream of RevocationEvents
    ///
    /// # Errors
    /// * `UnknownService` - Service not found
    /// * `ServiceRevoked` - Service has been revoked
    fn stream_events(
        &self,
        service_id: Uuid,
        last_sequence: u64,
    ) -> impl std::future::Future<Output = Result<impl Stream<Item = RevocationEvent> + Send>> + Send;

    /// Update webhook configuration
    ///
    /// # Arguments
    /// * `service_id` - Service ID
    /// * `webhook_config` - New webhook configuration
    ///
    /// # Errors
    /// * `UnknownService` - Service not found
    /// * `InvalidWebhookUrl` - Invalid webhook URL
    fn update_webhook_config(
        &self,
        service_id: Uuid,
        webhook_config: Option<WebhookConfig>,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Get integration service by ID
    ///
    /// # Arguments
    /// * `service_id` - Service ID
    ///
    /// # Errors
    /// * `UnknownService` - Service not found
    fn get_service(
        &self,
        service_id: Uuid,
    ) -> impl std::future::Future<Output = Result<IntegrationService>> + Send;
}
