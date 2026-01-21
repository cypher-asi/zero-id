//! Webhook delivery logic for the integrations service.

use crate::types::*;
use crate::webhook::{calculate_retry_delay, deliver_webhook, should_abandon_webhook};
use crate::{Error, Result};
use std::sync::Arc;
use uuid::Uuid;
use zero_auth_crypto::current_timestamp;
use zero_auth_storage::{column_families::*, Storage};

use super::{has_event_scope, should_deliver_event, IntegrationsService};

impl<S: Storage + 'static> IntegrationsService<S> {
    /// Queue webhook delivery
    pub(crate) async fn queue_webhook_delivery(&self, event: &RevocationEvent) -> Result<()> {
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
                attempted_at: current_timestamp(),
                next_attempt_at: Some(current_timestamp()),
                abandoned_at: None,
                http_status: None,
                error_message: None,
            };

            // Store delivery log
            let key = (service.service_id, event.event_id);
            self.storage
                .put(CF_WEBHOOK_DELIVERY_LOG, &key, &delivery_log)
                .await?;

            // Spawn delivery task
            self.spawn_webhook_delivery(service.service_id, event.clone(), webhook_config.clone())
                .await;
        }

        Ok(())
    }

    /// Spawn webhook delivery task
    pub(crate) async fn spawn_webhook_delivery(
        &self,
        service_id: Uuid,
        event: RevocationEvent,
        webhook_config: WebhookConfig,
    ) {
        let storage = self.storage.clone();

        tokio::spawn(async move {
            let mut attempt = 1;
            let first_attempt_at = current_timestamp();

            loop {
                let current_time = current_timestamp();

                // Check if should abandon
                if should_abandon_webhook(attempt, first_attempt_at, current_time) {
                    let _ =
                        Self::mark_webhook_abandoned(&storage, service_id, event.event_id).await;
                    break;
                }

                // Attempt delivery
                match deliver_webhook(&event, &webhook_config).await {
                    Ok(DeliveryStatus::Success) => {
                        // Success - update log and exit
                        let _ = Self::mark_webhook_success(
                            &storage,
                            service_id,
                            event.event_id,
                            attempt,
                        )
                        .await;
                        break;
                    }
                    Ok(DeliveryStatus::ClientError) => {
                        // Client error (4xx) - don't retry
                        let _ = Self::mark_webhook_client_error(
                            &storage,
                            service_id,
                            event.event_id,
                            attempt,
                        )
                        .await;
                        break;
                    }
                    Ok(DeliveryStatus::ServerError) | Err(_) => {
                        // Server error (5xx) or network error - retry
                        let delay = calculate_retry_delay(attempt);
                        let next_attempt_at = current_time + delay;

                        let _ = Self::mark_webhook_retry(
                            &storage,
                            service_id,
                            event.event_id,
                            attempt,
                            next_attempt_at,
                        )
                        .await;

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
    pub(crate) async fn mark_webhook_success(
        storage: &Arc<S>,
        service_id: Uuid,
        event_id: Uuid,
        attempt: u32,
    ) -> Result<()> {
        let key = (service_id, event_id);
        let mut log: WebhookDeliveryLog = storage
            .get(CF_WEBHOOK_DELIVERY_LOG, &key)
            .await?
            .ok_or(Error::Other("Delivery log not found".to_string()))?;

        log.status = DeliveryStatus::Success;
        log.attempt = attempt;
        log.attempted_at = current_timestamp();
        log.next_attempt_at = None;

        storage.put(CF_WEBHOOK_DELIVERY_LOG, &key, &log).await?;
        Ok(())
    }

    /// Mark webhook as client error (4xx)
    pub(crate) async fn mark_webhook_client_error(
        storage: &Arc<S>,
        service_id: Uuid,
        event_id: Uuid,
        attempt: u32,
    ) -> Result<()> {
        let key = (service_id, event_id);
        let mut log: WebhookDeliveryLog = storage
            .get(CF_WEBHOOK_DELIVERY_LOG, &key)
            .await?
            .ok_or(Error::Other("Delivery log not found".to_string()))?;

        log.status = DeliveryStatus::ClientError;
        log.attempt = attempt;
        log.attempted_at = current_timestamp();
        log.next_attempt_at = None;

        storage.put(CF_WEBHOOK_DELIVERY_LOG, &key, &log).await?;
        Ok(())
    }

    /// Mark webhook for retry
    pub(crate) async fn mark_webhook_retry(
        storage: &Arc<S>,
        service_id: Uuid,
        event_id: Uuid,
        attempt: u32,
        next_attempt_at: u64,
    ) -> Result<()> {
        let key = (service_id, event_id);
        let mut log: WebhookDeliveryLog = storage
            .get(CF_WEBHOOK_DELIVERY_LOG, &key)
            .await?
            .ok_or(Error::Other("Delivery log not found".to_string()))?;

        log.status = DeliveryStatus::Retrying;
        log.attempt = attempt;
        log.attempted_at = current_timestamp();
        log.next_attempt_at = Some(next_attempt_at);

        storage.put(CF_WEBHOOK_DELIVERY_LOG, &key, &log).await?;
        Ok(())
    }

    /// Mark webhook as abandoned
    pub(crate) async fn mark_webhook_abandoned(
        storage: &Arc<S>,
        service_id: Uuid,
        event_id: Uuid,
    ) -> Result<()> {
        let key = (service_id, event_id);
        let mut log: WebhookDeliveryLog = storage
            .get(CF_WEBHOOK_DELIVERY_LOG, &key)
            .await?
            .ok_or(Error::Other("Delivery log not found".to_string()))?;

        log.status = DeliveryStatus::Abandoned;
        log.abandoned_at = Some(current_timestamp());
        log.next_attempt_at = None;

        storage.put(CF_WEBHOOK_DELIVERY_LOG, &key, &log).await?;
        Ok(())
    }

    /// Clean up old webhook delivery logs
    ///
    /// Removes:
    /// - Abandoned webhooks older than 30 days
    /// - Successful deliveries older than 30 days
    pub async fn cleanup_old_webhooks(&self) -> Result<usize> {
        let _cutoff = current_timestamp() - (30 * 24 * 3600); // 30 days ago
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
}
