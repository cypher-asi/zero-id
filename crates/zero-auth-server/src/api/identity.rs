use axum::{
    extract::{Path, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use zero_auth_identity_core::{IdentityCore, MachineKey, CreateIdentityRequest as CoreCreateIdentityRequest, Approval, FreezeReason, RotationRequest, IdentityStatus};
use zero_auth_crypto::MachineKeyCapabilities;

use crate::{error::{ApiError, map_service_error}, extractors::AuthenticatedUser, state::AppState};

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateIdentityRequest {
    pub identity_id: Uuid,
    pub central_public_key: String, // hex
    pub authorization_signature: String, // hex
    pub machine_key: MachineKeyRequest,
    pub namespace_name: String,
}

#[derive(Debug, Deserialize)]
pub struct MachineKeyRequest {
    pub machine_id: Uuid,
    pub signing_public_key: String, // hex
    pub encryption_public_key: String, // hex
    pub capabilities: Vec<String>,
    pub device_name: String,
    pub device_platform: String,
}

#[derive(Debug, Serialize)]
pub struct CreateIdentityResponse {
    pub identity_id: Uuid,
    pub machine_id: Uuid,
    pub namespace_id: Uuid,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct GetIdentityResponse {
    pub identity_id: Uuid,
    pub central_public_key: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct FreezeCeremonyRequest {
    /// Machine IDs of approvers (for future multi-party approval)
    #[allow(dead_code)]
    pub approver_machine_ids: Vec<Uuid>,
    /// Approval signatures from approvers (for future multi-party approval)
    #[allow(dead_code)]
    pub approval_signatures: Vec<String>, // hex
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct UnfreezeCeremonyRequest {
    pub approver_machine_ids: Vec<Uuid>,
    pub approval_signatures: Vec<String>, // hex
}

#[derive(Debug, Deserialize)]
pub struct RecoveryCeremonyRequest {
    pub new_central_public_key: String, // hex
    pub approver_machine_ids: Vec<Uuid>,
    pub approval_signatures: Vec<String>, // hex
}

#[derive(Debug, Deserialize)]
pub struct RotationCeremonyRequest {
    pub new_central_public_key: String, // hex
    /// Signature from current central key (for future use)
    #[allow(dead_code)]
    pub rotation_signature: String, // hex from current central key
    pub approver_machine_ids: Vec<Uuid>,
    pub approval_signatures: Vec<String>, // hex
}

#[derive(Debug, Serialize)]
pub struct CeremonyResponse {
    pub success: bool,
    pub message: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /v1/identity
pub async fn create_identity(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateIdentityRequest>,
) -> Result<Json<CreateIdentityResponse>, ApiError> {
    // Parse hex strings
    let central_public_key = parse_hex_32(&req.central_public_key)?;
    let authorization_signature = parse_hex_64(&req.authorization_signature)?;
    let signing_public_key = parse_hex_32(&req.machine_key.signing_public_key)?;
    let encryption_public_key = parse_hex_32(&req.machine_key.encryption_public_key)?;

    // Parse capabilities
    let capabilities = parse_capabilities(&req.machine_key.capabilities)?;

    // Create machine key
    let machine_key = MachineKey {
        machine_id: req.machine_key.machine_id,
        identity_id: req.identity_id,
        namespace_id: req.identity_id, // Personal namespace
        signing_public_key,
        encryption_public_key,
        capabilities,
        epoch: 0,
        created_at: chrono::Utc::now().timestamp() as u64,
        expires_at: None,
        last_used_at: None,
        device_name: req.machine_key.device_name.clone(),
        device_platform: req.machine_key.device_platform.clone(),
        revoked: false,
        revoked_at: None,
    };

    // Create identity request
    let create_request = CoreCreateIdentityRequest {
        identity_id: req.identity_id,
        central_public_key,
        machine_key,
        authorization_signature: authorization_signature.to_vec(),
        namespace_name: Some(req.namespace_name),
        created_at: chrono::Utc::now().timestamp() as u64,
    };

    // Create identity
    let identity = state
        .identity_service
        .create_identity(create_request)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    // Personal namespace has same ID as identity
    let namespace_id = req.identity_id;

    Ok(Json(CreateIdentityResponse {
        identity_id: identity.identity_id,
        machine_id: req.machine_key.machine_id,
        namespace_id,
        created_at: chrono::DateTime::from_timestamp(identity.created_at as i64, 0)
            .unwrap()
            .to_rfc3339(),
    }))
}

/// GET /v1/identity/:identity_id
pub async fn get_identity(
    State(state): State<Arc<AppState>>,
    Path(identity_id): Path<Uuid>,
    _auth: AuthenticatedUser,
) -> Result<Json<GetIdentityResponse>, ApiError> {
    let identity = state
        .identity_service
        .get_identity(identity_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    let status_str = match identity.status {
        IdentityStatus::Active => "active",
        IdentityStatus::Disabled => "disabled",
        IdentityStatus::Frozen => "frozen",
        IdentityStatus::Deleted => "deleted",
    };

    Ok(Json(GetIdentityResponse {
        identity_id: identity.identity_id,
        central_public_key: hex::encode(identity.central_public_key),
        status: status_str.to_string(),
        created_at: chrono::DateTime::from_timestamp(identity.created_at as i64, 0)
            .unwrap()
            .to_rfc3339(),
    }))
}

/// POST /v1/identity/freeze
pub async fn freeze_identity(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<FreezeCeremonyRequest>,
) -> Result<Json<CeremonyResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    // Parse freeze reason
    let freeze_reason = match req.reason.as_str() {
        "security_incident" => FreezeReason::SecurityIncident,
        "suspicious_activity" => FreezeReason::SuspiciousActivity,
        "user_requested" => FreezeReason::UserRequested,
        "administrative" => FreezeReason::Administrative,
        _ => FreezeReason::Administrative,
    };

    // Execute freeze ceremony
    state
        .identity_service
        .freeze_identity(identity_id, freeze_reason)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(CeremonyResponse {
        success: true,
        message: "Identity frozen successfully".to_string(),
    }))
}

/// POST /v1/identity/unfreeze
pub async fn unfreeze_identity(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<UnfreezeCeremonyRequest>,
) -> Result<Json<CeremonyResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    // Parse signatures into Approvals
    let mut approvals = Vec::new();
    for (i, sig_hex) in req.approval_signatures.iter().enumerate() {
        let signature_bytes = hex::decode(sig_hex)
            .map_err(|_| ApiError::InvalidRequest("Invalid hex encoding".to_string()))?;
        
        approvals.push(Approval {
            machine_id: req.approver_machine_ids[i],
            signature: signature_bytes,
            timestamp: chrono::Utc::now().timestamp() as u64,
        });
    }

    // Execute unfreeze ceremony
    state
        .identity_service
        .unfreeze_identity(identity_id, approvals)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(CeremonyResponse {
        success: true,
        message: "Identity unfrozen successfully".to_string(),
    }))
}

/// POST /v1/identity/recovery
pub async fn recovery_ceremony(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<RecoveryCeremonyRequest>,
) -> Result<Json<CeremonyResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;
    let new_central_public_key = parse_hex_32(&req.new_central_public_key)?;

    // Parse signatures into Approvals
    let mut approvals = Vec::new();
    for (i, sig_hex) in req.approval_signatures.iter().enumerate() {
        let signature_bytes = hex::decode(sig_hex)
            .map_err(|_| ApiError::InvalidRequest("Invalid hex encoding".to_string()))?;
        
        approvals.push(Approval {
            machine_id: req.approver_machine_ids[i],
            signature: signature_bytes,
            timestamp: chrono::Utc::now().timestamp() as u64,
        });
    }

    // Create a recovery machine key (placeholder - should come from request)
    let recovery_machine_key = MachineKey {
        machine_id: Uuid::new_v4(),
        identity_id,
        namespace_id: identity_id,
        signing_public_key: new_central_public_key,
        encryption_public_key: new_central_public_key,
        capabilities: MachineKeyCapabilities::FULL_DEVICE,
        epoch: 1,
        created_at: chrono::Utc::now().timestamp() as u64,
        expires_at: None,
        last_used_at: None,
        device_name: "Recovery Device".to_string(),
        device_platform: "unknown".to_string(),
        revoked: false,
        revoked_at: None,
    };

    // Execute recovery ceremony
    state
        .identity_service
        .initiate_recovery(identity_id, recovery_machine_key, approvals)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(CeremonyResponse {
        success: true,
        message: "Identity recovered successfully".to_string(),
    }))
}

/// POST /v1/identity/rotation
pub async fn rotation_ceremony(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<RotationCeremonyRequest>,
) -> Result<Json<CeremonyResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;
    let new_central_public_key = parse_hex_32(&req.new_central_public_key)?;

    // Parse signatures into Approvals
    let mut approvals = Vec::new();
    for (i, sig_hex) in req.approval_signatures.iter().enumerate() {
        let signature_bytes = hex::decode(sig_hex)
            .map_err(|_| ApiError::InvalidRequest("Invalid hex encoding".to_string()))?;
        
        approvals.push(Approval {
            machine_id: req.approver_machine_ids[i],
            signature: signature_bytes,
            timestamp: chrono::Utc::now().timestamp() as u64,
        });
    }

    // Create rotation request
    let rotation_request = RotationRequest {
        identity_id,
        new_central_public_key,
        approvals,
        new_machines: Vec::new(), // TODO: Should come from request
    };

    // Execute rotation ceremony
    state
        .identity_service
        .rotate_neural_key(rotation_request)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(CeremonyResponse {
        success: true,
        message: "Central key rotated successfully".to_string(),
    }))
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
