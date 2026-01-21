use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use zero_auth_identity_core::{IdentityCore, MachineKey};

use crate::{
    error::{map_service_error, ApiError},
    extractors::AuthenticatedUser,
    state::AppState,
};

use super::helpers::{format_timestamp_rfc3339, parse_capabilities, parse_hex_32, parse_hex_64};

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct EnrollMachineRequest {
    pub machine_id: Uuid,
    pub namespace_id: Option<Uuid>,
    pub signing_public_key: String,    // hex
    pub encryption_public_key: String, // hex
    pub capabilities: Vec<String>,
    pub device_name: String,
    pub device_platform: String,
    pub authorization_signature: String, // hex
}

#[derive(Debug, Serialize)]
pub struct EnrollMachineResponse {
    pub machine_id: Uuid,
    pub namespace_id: Uuid,
    pub enrolled_at: String,
}

#[derive(Debug, Deserialize)]
pub struct ListMachinesQuery {
    pub namespace_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct MachineInfo {
    pub machine_id: Uuid,
    pub device_name: String,
    pub device_platform: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked: bool,
}

#[derive(Debug, Serialize)]
pub struct ListMachinesResponse {
    pub machines: Vec<MachineInfo>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeMachineRequest {
    pub reason: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /v1/machines/enroll
pub async fn enroll_machine(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    ctx: crate::request_context::RequestContext,
    Json(req): Json<EnrollMachineRequest>,
) -> Result<Json<EnrollMachineResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;
    let mfa_verified = auth.claims.mfa_verified;

    // Parse hex strings
    let signing_public_key = parse_hex_32(&req.signing_public_key)?;
    let encryption_public_key = parse_hex_32(&req.encryption_public_key)?;
    let authorization_signature = parse_hex_64(&req.authorization_signature)?;

    // Parse capabilities
    let capabilities = parse_capabilities(&req.capabilities)?;

    // Default namespace to personal namespace if not provided
    let namespace_id = req.namespace_id.unwrap_or(identity_id);

    // Create machine key
    let machine_key = MachineKey {
        machine_id: req.machine_id,
        identity_id,
        namespace_id,
        signing_public_key,
        encryption_public_key,
        capabilities,
        epoch: 0,
        created_at: chrono::Utc::now().timestamp() as u64,
        expires_at: None,
        last_used_at: None,
        device_name: req.device_name.clone(),
        device_platform: req.device_platform.clone(),
        revoked: false,
        revoked_at: None,
    };

    // Enroll machine
    let machine_id = state
        .identity_service
        .enroll_machine_key(
            identity_id,
            machine_key,
            authorization_signature.to_vec(),
            mfa_verified,
            ctx.ip_address,
            ctx.user_agent,
        )
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(EnrollMachineResponse {
        machine_id,
        namespace_id,
        enrolled_at: chrono::Utc::now().to_rfc3339(),
    }))
}

/// GET /v1/machines
pub async fn list_machines(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListMachinesQuery>,
    auth: AuthenticatedUser,
) -> Result<Json<ListMachinesResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;
    let namespace_id = query.namespace_id.unwrap_or(identity_id);

    // Get machines for namespace
    let machines = state
        .identity_service
        .list_machines(identity_id, namespace_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    let machine_infos: Result<Vec<_>, ApiError> = machines
        .into_iter()
        .map(|m| {
            let created_at = format_timestamp_rfc3339(m.created_at)?;

            let last_used_at = m.last_used_at.map(format_timestamp_rfc3339).transpose()?;

            Ok(MachineInfo {
                machine_id: m.machine_id,
                device_name: m.device_name,
                device_platform: m.device_platform,
                created_at,
                last_used_at,
                revoked: m.revoked,
            })
        })
        .collect();

    Ok(Json(ListMachinesResponse {
        machines: machine_infos?,
    }))
}

/// DELETE /v1/machines/:machine_id
pub async fn revoke_machine(
    State(state): State<Arc<AppState>>,
    Path(machine_id): Path<Uuid>,
    auth: AuthenticatedUser,
    ctx: crate::request_context::RequestContext,
    Json(req): Json<RevokeMachineRequest>,
) -> Result<StatusCode, ApiError> {
    let _identity_id = auth.claims.identity_id()?;
    let revoker_machine_id = auth.claims.machine_id()?;
    let mfa_verified = auth.claims.mfa_verified;

    // Revoke machine
    state
        .identity_service
        .revoke_machine_key(
            machine_id,
            revoker_machine_id,
            req.reason,
            mfa_verified,
            ctx.ip_address,
            ctx.user_agent,
        )
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(StatusCode::NO_CONTENT)
}
