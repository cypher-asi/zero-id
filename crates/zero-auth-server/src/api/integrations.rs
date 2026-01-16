use axum::{
    extract::State,
    response::{
        sse::{Event, KeepAlive, Sse},
        Json,
    },
};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use uuid::Uuid;
use zero_auth_integrations::{Integrations, RegisterServiceRequest as CoreRegisterServiceRequest, WebhookConfig};

use crate::{error::ApiError, state::AppState};

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct RegisterServiceRequest {
    pub service_name: String,
    /// Service ID (for future use in service management)
    #[allow(dead_code)]
    pub service_id: Uuid,
    pub cert_fingerprint: String, // hex
    /// Scopes requested by service (for future authorization)
    #[allow(dead_code)]
    pub scopes: Vec<String>,
    pub namespace_filters: Vec<Uuid>,
    pub webhook_url: Option<String>,
    pub webhook_secret: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterServiceResponse {
    pub service_id: Uuid,
    pub registered_at: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /v1/integrations/register
pub async fn register_service(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterServiceRequest>,
) -> Result<Json<RegisterServiceResponse>, ApiError> {
    // Parse cert fingerprint
    let cert_fingerprint_bytes = hex::decode(&req.cert_fingerprint)
        .map_err(|_| ApiError::InvalidRequest("Invalid cert fingerprint".to_string()))?;
    
    if cert_fingerprint_bytes.len() != 32 {
        return Err(ApiError::InvalidRequest("Cert fingerprint must be 32 bytes".to_string()));
    }
    
    let mut cert_fingerprint = [0u8; 32];
    cert_fingerprint.copy_from_slice(&cert_fingerprint_bytes);

    // Parse scopes (for now, just use empty vec - would need proper scope parsing)
    let scopes = Vec::new();

    // Create webhook config if provided
    let webhook_config = if let (Some(webhook_url), Some(webhook_secret)) = (req.webhook_url, req.webhook_secret) {
        let secret_bytes = hex::decode(&webhook_secret)
            .map_err(|_| ApiError::InvalidRequest("Invalid webhook secret encoding".to_string()))?;
        if secret_bytes.len() != 32 {
            return Err(ApiError::InvalidRequest("Webhook secret must be 32 bytes".to_string()));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_bytes);
        
        Some(WebhookConfig {
            url: webhook_url,
            secret,
            enabled: true,
        })
    } else {
        None
    };

    // Create registration request
    let register_request = CoreRegisterServiceRequest {
        service_name: req.service_name,
        client_cert_fingerprint: cert_fingerprint,
        namespace_filter: req.namespace_filters,
        scopes,
        webhook_config,
    };

    // Register service
    let service_id = state
        .integrations_service
        .register_service(register_request)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;

    Ok(Json(RegisterServiceResponse {
        service_id,
        registered_at: chrono::Utc::now().to_rfc3339(),
    }))
}

/// GET /v1/events/stream
pub async fn event_stream(
    State(_state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // Subscribe to event stream
    // TODO: Implement proper event subscription from integrations service
    // For now, create a placeholder stream that sends keepalive messages
    let (_tx, receiver) = tokio::sync::broadcast::channel::<serde_json::Value>(100);

    // Convert to SSE stream
    let stream = BroadcastStream::new(receiver)
        .filter_map(|result| {
            match result {
                Ok(event_json) => {
                    // Convert event JSON to SSE format
                    let event_type = event_json.get("event_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");

                    let event_id = event_json.get("sequence")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);

                    Some(Ok(Event::default()
                        .id(event_id.to_string())
                        .event(event_type)
                        .data(event_json.to_string())))
                }
                Err(_) => None,
            }
        });

    Sse::new(stream).keep_alive(KeepAlive::default())
}
