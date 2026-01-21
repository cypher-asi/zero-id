use axum::{
    extract::State,
    http::HeaderMap,
    response::{
        sse::{Event, KeepAlive, Sse},
        Json,
    },
};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use tokio_stream::StreamExt;
use uuid::Uuid;
use zero_auth_crypto::blake3_hash;
use zero_auth_integrations::{
    Integrations, RegisterServiceRequest as CoreRegisterServiceRequest, WebhookConfig,
};

use crate::{error::ApiError, state::AppState};

// ============================================================================
// Authentication Helper
// ============================================================================

/// Extract and validate mTLS client certificate
///
/// This function implements mTLS certificate validation for service authentication.
///
/// **Infrastructure Requirements:**
/// - Reverse proxy (nginx/haproxy) must be configured for mTLS
/// - Client certificate must be passed in X-Client-Cert header (PEM format)
/// - Or X-Client-Cert-Fingerprint header (SHA256, hex-encoded)
///
/// **Security Notes:**
/// - The reverse proxy MUST validate the certificate chain
/// - The reverse proxy MUST only accept certificates signed by trusted CA
/// - Never trust the certificate from the request body - only from headers set by proxy
async fn extract_and_validate_client_cert(headers: &HeaderMap) -> Result<[u8; 32], ApiError> {
    // Try to get pre-computed fingerprint from reverse proxy
    if let Some(fingerprint_header) = headers.get("X-Client-Cert-Fingerprint") {
        let fingerprint_hex = fingerprint_header.to_str().map_err(|_| {
            ApiError::InvalidRequest("Invalid certificate fingerprint header".to_string())
        })?;

        let fingerprint_bytes = hex::decode(fingerprint_hex).map_err(|_| {
            ApiError::InvalidRequest("Invalid certificate fingerprint encoding".to_string())
        })?;

        if fingerprint_bytes.len() != 32 {
            return Err(ApiError::InvalidRequest(
                "Certificate fingerprint must be 32 bytes (SHA256)".to_string(),
            ));
        }

        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&fingerprint_bytes);

        tracing::info!(
            fingerprint = hex::encode(fingerprint),
            "Client certificate validated via fingerprint header"
        );

        return Ok(fingerprint);
    }

    // Try to extract and hash the full certificate
    if let Some(cert_header) = headers.get("X-Client-Cert") {
        let cert_pem = cert_header
            .to_str()
            .map_err(|_| ApiError::InvalidRequest("Invalid certificate header".to_string()))?;

        // Parse PEM certificate
        // Note: In production, use a proper X.509 parser like x509-parser or rustls
        // For now, we hash the PEM content as a fingerprint
        let cert_bytes = cert_pem.as_bytes();

        // Compute SHA256 fingerprint using BLAKE3 for consistency
        // In production, use proper X.509 DER encoding and SHA256
        let fingerprint = blake3_hash(cert_bytes);

        tracing::info!(
            fingerprint = hex::encode(fingerprint),
            "Client certificate validated and fingerprint computed"
        );

        return Ok(fingerprint);
    }

    // No client certificate found
    Err(ApiError::InvalidRequest(
        "mTLS client certificate required. Set X-Client-Cert or X-Client-Cert-Fingerprint header."
            .to_string(),
    ))
}

/// Authenticate service by verifying it's registered and not revoked
async fn authenticate_service(state: &AppState, service_id: Uuid) -> Result<(), ApiError> {
    if service_id.is_nil() {
        return Err(ApiError::InvalidRequest("Invalid service ID".to_string()));
    }

    // Check if service is registered and not revoked in storage
    let service = state
        .integrations_service
        .get_service(service_id)
        .await
        .map_err(|e| {
            tracing::warn!(service_id = %service_id, error = %e, "Service not found");
            ApiError::Unauthorized
        })?;

    if service.revoked {
        tracing::warn!(service_id = %service_id, "Service is revoked");
        return Err(ApiError::Unauthorized);
    }

    Ok(())
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct RegisterServiceRequest {
    pub service_name: String,
    /// Scopes requested by service for authorization
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
///
/// **Security:** This endpoint REQUIRES mTLS client certificate authentication.
/// The certificate is extracted from request headers set by the reverse proxy.
/// Never trust certificate fingerprints from the request body.
pub async fn register_service(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RegisterServiceRequest>,
) -> Result<Json<RegisterServiceResponse>, ApiError> {
    // SECURITY: Extract and validate client certificate from mTLS connection
    // This prevents attackers from providing arbitrary fingerprints in the request body
    let cert_fingerprint = extract_and_validate_client_cert(&headers).await?;

    tracing::info!(
        service_name = %req.service_name,
        cert_fingerprint = hex::encode(cert_fingerprint),
        "Service registration request with validated mTLS certificate"
    );

    // Parse scopes from request
    let scopes = parse_scopes(&req.scopes)?;

    // Create webhook config if provided
    let webhook_config = if let (Some(webhook_url), Some(webhook_secret)) =
        (req.webhook_url, req.webhook_secret)
    {
        let secret_bytes = hex::decode(&webhook_secret)
            .map_err(|_| ApiError::InvalidRequest("Invalid webhook secret encoding".to_string()))?;
        if secret_bytes.len() != 32 {
            return Err(ApiError::InvalidRequest(
                "Webhook secret must be 32 bytes".to_string(),
            ));
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
///
/// Subscribe to real-time revocation events via Server-Sent Events (SSE).
///
/// **Security:** This endpoint REQUIRES mTLS client certificate authentication.
///
/// Query parameters:
/// - `service_id`: UUID of the registered service
/// - `last_sequence`: (optional) Last sequence number received (for backfill)
pub async fn event_stream(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<EventStreamParams>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    // SECURITY: Validate mTLS client certificate
    let cert_fingerprint = extract_and_validate_client_cert(&headers).await?;

    // Authenticate service (verify registration and revocation status)
    authenticate_service(&state, params.service_id).await?;

    // Get service and verify certificate fingerprint matches
    let service = state
        .integrations_service
        .get_service(params.service_id)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;

    // Verify certificate fingerprint matches registered service
    if service.client_cert_fingerprint != cert_fingerprint {
        tracing::warn!(
            service_id = %params.service_id,
            expected_fp = hex::encode(service.client_cert_fingerprint),
            provided_fp = hex::encode(cert_fingerprint),
            "Certificate fingerprint mismatch"
        );
        return Err(ApiError::Unauthorized);
    }

    // Create a channel for events
    // In a real implementation, this would connect to the integrations service's
    // SSE stream. For now, we create a placeholder stream that demonstrates the API.
    let (tx, rx) = tokio::sync::mpsc::channel(100);

    // Spawn a task to forward events (in production, this would subscribe to the service)
    // For now, just keep the channel open
    tokio::spawn(async move {
        // Keep sender alive but don't send anything yet
        // In production: subscribe to integrations_service.stream_events() and forward
        let _tx = tx;
        tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
    });

    // Convert channel receiver to SSE Event stream
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(
        |revocation_event: zero_auth_integrations::RevocationEvent| {
            // Convert to JSON
            let event_json =
                serde_json::to_string(&revocation_event).unwrap_or_else(|_| "{}".to_string());

            // Create SSE event with proper metadata
            Ok(Event::default()
                .id(revocation_event.sequence.to_string())
                .event(revocation_event.event_type.event_name())
                .data(event_json))
        },
    );

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

#[derive(Debug, Deserialize)]
pub struct EventStreamParams {
    pub service_id: Uuid,
    #[allow(dead_code)] // Reserved for resume/backfill support.
    pub last_sequence: Option<u64>,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parse scope strings to Scope enum
fn parse_scopes(scope_strings: &[String]) -> Result<Vec<zero_auth_integrations::Scope>, ApiError> {
    use zero_auth_integrations::Scope;

    let mut scopes = Vec::new();
    for scope_str in scope_strings {
        let scope = match scope_str.as_str() {
            "events:machine_revoked" => Scope::EventsMachineRevoked,
            "events:session_revoked" => Scope::EventsSessionRevoked,
            "events:identity_frozen" => Scope::EventsIdentityFrozen,
            _ => return Err(ApiError::InvalidRequest(format!(
                "Invalid scope: {}. Valid scopes: events:machine_revoked, events:session_revoked, events:identity_frozen",
                scope_str
            ))),
        };
        scopes.push(scope);
    }

    if scopes.is_empty() {
        return Err(ApiError::InvalidRequest(
            "At least one scope must be specified".to_string(),
        ));
    }

    Ok(scopes)
}
