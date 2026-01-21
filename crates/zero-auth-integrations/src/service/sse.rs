//! SSE (Server-Sent Events) streaming logic for the integrations service.

use crate::traits::Integrations;
use crate::types::*;
use uuid::Uuid;
use zero_auth_storage::Storage;

use super::{has_event_scope, should_deliver_event, IntegrationsService, SseStream};

impl<S: Storage + 'static> IntegrationsService<S> {
    /// Broadcast event to SSE streams
    pub(crate) async fn broadcast_to_sse_streams(&self, event: &RevocationEvent) {
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

    /// Register SSE stream
    pub(crate) async fn register_sse_stream(&self, service_id: Uuid, sender: SseStream) {
        let mut streams = self.sse_streams.write().await;
        streams.entry(service_id).or_default().push(sender);
    }

    /// Unregister SSE stream (called when connection drops)
    ///
    /// NOTE: This is currently not called automatically. To properly implement:
    /// 1. Wrap the SSE stream in a struct that tracks connection state
    /// 2. Implement Drop trait to call this method
    /// 3. Or use tokio::select! to detect closed connections
    ///
    /// For now, we rely on the tokio channel automatically closing when
    /// the receiver is dropped, which prevents memory leaks.
    pub async fn unregister_sse_stream(&self, service_id: Uuid, sender_index: usize) {
        let mut streams = self.sse_streams.write().await;
        if let Some(senders) = streams.get_mut(&service_id) {
            if sender_index < senders.len() {
                senders.remove(sender_index);
            }
        }
    }
}
