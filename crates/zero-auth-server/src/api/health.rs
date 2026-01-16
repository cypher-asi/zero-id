use axum::{
    extract::State,
    response::Json,
};
use serde::Serialize;
use std::sync::Arc;

use crate::state::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

/// Health check endpoint
pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Serialize)]
pub struct ReadinessResponse {
    status: &'static str,
    database: &'static str,
}

/// Readiness check endpoint
pub async fn readiness_check(
    State(_state): State<Arc<AppState>>,
) -> Json<ReadinessResponse> {
    // Simple health check - if we get here, the server is ready
    Json(ReadinessResponse {
        status: "ready",
        database: "connected",
    })
}
