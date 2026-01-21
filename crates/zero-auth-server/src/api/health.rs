use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde::Serialize;
use std::sync::Arc;
use zero_auth_storage::Storage;

use crate::state::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    version: &'static str,
    timestamp: u64,
}

/// Health check endpoint (liveness probe)
///
/// Returns 200 OK if the server process is running.
/// This endpoint does not check dependencies.
pub async fn health_check() -> Json<HealthResponse> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        timestamp,
    })
}

#[derive(Serialize)]
pub struct ReadinessResponse {
    status: &'static str,
    database: &'static str,
    timestamp: u64,
}

/// Readiness check endpoint (readiness probe)
///
/// Returns 200 OK if the server is ready to accept traffic.
/// Checks database connectivity and other critical dependencies.
pub async fn readiness_check(State(state): State<Arc<AppState>>) -> Response {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Check database connectivity by attempting a simple operation
    let db_status = match state
        .storage
        .exists("identities", &"health_check_key")
        .await
    {
        Ok(_) => "connected",
        Err(e) => {
            tracing::error!("Database health check failed: {}", e);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ReadinessResponse {
                    status: "not_ready",
                    database: "disconnected",
                    timestamp,
                }),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(ReadinessResponse {
            status: "ready",
            database: db_status,
            timestamp,
        }),
    )
        .into_response()
}
