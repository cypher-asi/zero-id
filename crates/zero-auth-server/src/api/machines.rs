use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use zero_auth_identity_core::{IdentityCore, MachineKey};
use zero_auth_crypto::MachineKeyCapabilities;

use crate::{error::{ApiError, map_service_error}, extractors::AuthenticatedUser, state::AppState};

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct EnrollMachineRequest {
    pub machine_id: Uuid,
    pub namespace_id: Option<Uuid>,
    pub signing_public_key: String, // hex
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
    Json(req): Json<EnrollMachineRequest>,
) -> Result<Json<EnrollMachineResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;

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
        .enroll_machine_key(identity_id, machine_key, authorization_signature.to_vec())
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

    let machine_infos = machines
        .into_iter()
        .map(|m| MachineInfo {
            machine_id: m.machine_id,
            device_name: m.device_name,
            device_platform: m.device_platform,
            created_at: chrono::DateTime::from_timestamp(m.created_at as i64, 0)
                .unwrap()
                .to_rfc3339(),
            last_used_at: m.last_used_at.map(|t| {
                chrono::DateTime::from_timestamp(t as i64, 0)
                    .unwrap()
                    .to_rfc3339()
            }),
            revoked: m.revoked,
        })
        .collect();

    Ok(Json(ListMachinesResponse {
        machines: machine_infos,
    }))
}

/// DELETE /v1/machines/:machine_id
pub async fn revoke_machine(
    State(state): State<Arc<AppState>>,
    Path(machine_id): Path<Uuid>,
    auth: AuthenticatedUser,
    Json(req): Json<RevokeMachineRequest>,
) -> Result<StatusCode, ApiError> {
    let _identity_id = auth.claims.identity_id()?;
    let revoker_machine_id = auth.claims.machine_id()?;

    // Revoke machine
    state
        .identity_service
        .revoke_machine_key(machine_id, revoker_machine_id, req.reason)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Helper Functions
// ============================================================================

fn parse_hex_32(hex_str: &str) -> Result<[u8; 32], ApiError> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| ApiError::InvalidRequest("Invalid hex encoding".to_string()))?;
    if bytes.len() != 32 {
        return Err(ApiError::InvalidRequest("Expected 32 bytes".to_string()));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

fn parse_hex_64(hex_str: &str) -> Result<[u8; 64], ApiError> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| ApiError::InvalidRequest("Invalid hex encoding".to_string()))?;
    if bytes.len() != 64 {
        return Err(ApiError::InvalidRequest("Expected 64 bytes".to_string()));
    }
    let mut array = [0u8; 64];
    array.copy_from_slice(&bytes);
    Ok(array)
}

fn parse_capabilities(caps: &[String]) -> Result<MachineKeyCapabilities, ApiError> {
    let mut result = MachineKeyCapabilities::empty();
    for s in caps {
        match s.as_str() {
            "FULL_DEVICE" => result |= MachineKeyCapabilities::FULL_DEVICE,
            "AUTHENTICATE" => result |= MachineKeyCapabilities::AUTHENTICATE,
            "SIGN" => result |= MachineKeyCapabilities::SIGN,
            "ENCRYPT" => result |= MachineKeyCapabilities::ENCRYPT,
            "SVK_UNWRAP" => result |= MachineKeyCapabilities::SVK_UNWRAP,
            "MLS_MESSAGING" => result |= MachineKeyCapabilities::MLS_MESSAGING,
            "VAULT_OPERATIONS" => result |= MachineKeyCapabilities::VAULT_OPERATIONS,
            "SERVICE_MACHINE" => result |= MachineKeyCapabilities::SERVICE_MACHINE,
            _ => return Err(ApiError::InvalidRequest(format!("Invalid capability: {}", s))),
        }
    }
    Ok(result)
}
