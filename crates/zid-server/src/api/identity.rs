use axum::{
    extract::{Path, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use zid_crypto::MachineKeyCapabilities;
use zid_identity_core::{
    Approval, CreateIdentityRequest as CoreCreateIdentityRequest, FreezeReason, IdentityCore,
    IdentityStatus, MachineKey, RotationRequest,
};

use crate::{
    error::{map_service_error, ApiError},
    extractors::{AuthenticatedUser, JsonWithErrors},
    state::AppState,
};

use super::helpers::{format_timestamp_rfc3339, parse_capabilities, parse_hex_32, parse_hex_64, parse_key_scheme, parse_pq_signing_key, parse_pq_encryption_key};
use zid_crypto::KeyScheme;

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateIdentityRequest {
    pub identity_id: Uuid,
    pub identity_signing_public_key: String, // hex
    pub authorization_signature: String,     // hex
    pub machine_key: MachineKeyRequest,
    pub namespace_name: String,
    pub created_at: u64, // Unix timestamp - must match the timestamp used to create the signature
}

#[derive(Debug, Deserialize)]
pub struct MachineKeyRequest {
    pub machine_id: Uuid,
    pub signing_public_key: String,    // hex
    pub encryption_public_key: String, // hex
    pub capabilities: Vec<String>,
    pub device_name: String,
    pub device_platform: String,
    /// Key scheme: "classical" (default) or "pq_hybrid"
    pub key_scheme: Option<String>,
    /// ML-DSA-65 public key (hex, 3904 chars)
    pub pq_signing_public_key: Option<String>,
    /// ML-KEM-768 public key (hex, 2368 chars)
    pub pq_encryption_public_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateIdentityResponse {
    pub identity_id: Uuid,
    pub machine_id: Uuid,
    pub namespace_id: Uuid,
    pub key_scheme: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct GetIdentityResponse {
    pub identity_id: Uuid,
    pub identity_signing_public_key: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct FreezeCeremonyRequest {
    /// Machine IDs of approvers for multi-party approval
    pub approver_machine_ids: Vec<Uuid>,
    /// Approval signatures from approvers for multi-party approval  
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
    pub new_identity_signing_public_key: String, // hex
    pub approver_machine_ids: Vec<Uuid>,
    pub approval_signatures: Vec<String>, // hex
}

#[derive(Debug, Deserialize)]
pub struct RotationCeremonyRequest {
    pub new_identity_signing_public_key: String, // hex
    /// Signature from current identity signing key proving authorization
    pub rotation_signature: String, // hex from current identity signing key
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
    JsonWithErrors(req): JsonWithErrors<CreateIdentityRequest>,
) -> Result<Json<CreateIdentityResponse>, ApiError> {
    // Parse hex strings
    let identity_signing_public_key = parse_hex_32(&req.identity_signing_public_key)?;
    let authorization_signature = parse_hex_64(&req.authorization_signature)?;
    let signing_public_key = parse_hex_32(&req.machine_key.signing_public_key)?;
    let encryption_public_key = parse_hex_32(&req.machine_key.encryption_public_key)?;

    // Parse capabilities
    let capabilities = parse_capabilities(&req.machine_key.capabilities)?;

    // Parse key scheme (default to classical)
    let key_scheme = parse_key_scheme(req.machine_key.key_scheme.as_deref())?;

    // Parse PQ keys if scheme is pq_hybrid
    let (pq_signing_public_key, pq_encryption_public_key) = match key_scheme {
        KeyScheme::Classical => (None, None),
        KeyScheme::PqHybrid => {
            let pq_sign = req.machine_key.pq_signing_public_key.as_ref()
                .ok_or_else(|| ApiError::InvalidRequest(
                    "pq_signing_public_key required for pq_hybrid scheme".to_string()
                ))
                .and_then(|s| parse_pq_signing_key(s))?;
            let pq_enc = req.machine_key.pq_encryption_public_key.as_ref()
                .ok_or_else(|| ApiError::InvalidRequest(
                    "pq_encryption_public_key required for pq_hybrid scheme".to_string()
                ))
                .and_then(|s| parse_pq_encryption_key(s))?;
            (Some(pq_sign), Some(pq_enc))
        }
    };

    // Create machine key
    let machine_key = MachineKey {
        machine_id: req.machine_key.machine_id,
        identity_id: req.identity_id,
        namespace_id: req.identity_id, // Personal namespace
        signing_public_key,
        encryption_public_key,
        capabilities,
        epoch: 0,
        created_at: req.created_at, // Use client-provided timestamp
        expires_at: None,
        last_used_at: None,
        device_name: req.machine_key.device_name.clone(),
        device_platform: req.machine_key.device_platform.clone(),
        revoked: false,
        revoked_at: None,
        key_scheme,
        pq_signing_public_key,
        pq_encryption_public_key,
    };

    // Create identity request
    let create_request = CoreCreateIdentityRequest {
        identity_id: req.identity_id,
        identity_signing_public_key,
        machine_key,
        authorization_signature: authorization_signature.to_vec(),
        namespace_name: Some(req.namespace_name),
        created_at: req.created_at, // Use client-provided timestamp for signature verification
    };

    // Create identity
    let identity = state
        .identity_service
        .create_identity(create_request)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    // Personal namespace has same ID as identity
    let namespace_id = req.identity_id;

    let key_scheme_str = match key_scheme {
        KeyScheme::Classical => "classical",
        KeyScheme::PqHybrid => "pq_hybrid",
    };

    Ok(Json(CreateIdentityResponse {
        identity_id: identity.identity_id,
        machine_id: req.machine_key.machine_id,
        namespace_id,
        key_scheme: key_scheme_str.to_string(),
        created_at: format_timestamp_rfc3339(identity.created_at)?,
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
        identity_signing_public_key: hex::encode(identity.identity_signing_public_key),
        status: status_str.to_string(),
        created_at: format_timestamp_rfc3339(identity.created_at)?,
    }))
}

/// POST /v1/identity/freeze
pub async fn freeze_identity(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<FreezeCeremonyRequest>,
) -> Result<Json<CeremonyResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    // Check tier - freeze requires self-sovereign
    let identity = state
        .identity_service
        .get_identity(identity_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;
    
    if identity.tier == zid_identity_core::IdentityTier::Managed {
        return Err(ApiError::InvalidRequest(
            "Freeze ceremony requires self-sovereign identity. Please upgrade your identity first.".to_string()
        ));
    }

    // Parse freeze reason
    let freeze_reason = match req.reason.as_str() {
        "security_incident" => FreezeReason::SecurityIncident,
        "suspicious_activity" => FreezeReason::SuspiciousActivity,
        "user_requested" => FreezeReason::UserRequested,
        "administrative" => FreezeReason::Administrative,
        _ => FreezeReason::Administrative,
    };

    // Parse approvals for freeze ceremony
    let mut approvals = Vec::new();

    // Check if multi-party approval is provided for high-risk freeze
    if matches!(
        freeze_reason,
        FreezeReason::SecurityIncident | FreezeReason::SuspiciousActivity
    ) {
        // For high-risk freezes, require at least one approval
        if req.approver_machine_ids.is_empty() || req.approval_signatures.is_empty() {
            return Err(ApiError::InvalidRequest(
                "Multi-party approval required for security-related freeze".to_string(),
            ));
        }

        // Verify approval count matches
        if req.approver_machine_ids.len() != req.approval_signatures.len() {
            return Err(ApiError::InvalidRequest(
                "Number of approvers must match number of signatures".to_string(),
            ));
        }

        // Parse signatures into Approvals
        for (i, sig_hex) in req.approval_signatures.iter().enumerate() {
            let signature_bytes = hex::decode(sig_hex)
                .map_err(|_| ApiError::InvalidRequest("Invalid hex encoding".to_string()))?;

            approvals.push(Approval {
                machine_id: req.approver_machine_ids[i],
                signature: signature_bytes,
                timestamp: chrono::Utc::now().timestamp() as u64,
            });
        }
    }

    // Execute freeze ceremony with cryptographic verification of approvals
    state
        .identity_service
        .freeze_identity(identity_id, freeze_reason, approvals)
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

    // Check tier - unfreeze requires self-sovereign
    let identity = state
        .identity_service
        .get_identity(identity_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;
    
    if identity.tier == zid_identity_core::IdentityTier::Managed {
        return Err(ApiError::InvalidRequest(
            "Unfreeze ceremony requires self-sovereign identity. Please upgrade your identity first.".to_string()
        ));
    }

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

    // Check tier - recovery ceremony requires self-sovereign
    let identity = state
        .identity_service
        .get_identity(identity_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;
    
    if identity.tier == zid_identity_core::IdentityTier::Managed {
        return Err(ApiError::InvalidRequest(
            "Recovery ceremony requires self-sovereign identity. Managed identities use multi-method recovery via /v1/identity/recover endpoint.".to_string()
        ));
    }

    let new_identity_signing_public_key = parse_hex_32(&req.new_identity_signing_public_key)?;

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
        signing_public_key: new_identity_signing_public_key,
        encryption_public_key: new_identity_signing_public_key,
        capabilities: MachineKeyCapabilities::FULL_DEVICE,
        epoch: 1,
        created_at: chrono::Utc::now().timestamp() as u64,
        expires_at: None,
        last_used_at: None,
        device_name: "Recovery Device".to_string(),
        device_platform: "unknown".to_string(),
        revoked: false,
        revoked_at: None,
        key_scheme: Default::default(),
        pq_signing_public_key: None,
        pq_encryption_public_key: None,
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
    // Rotation is a high-risk operation - require MFA
    auth.claims.require_mfa()?;

    let identity_id = auth.claims.identity_id()?;

    // Check tier - rotation ceremony requires self-sovereign
    let identity = state
        .identity_service
        .get_identity(identity_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;
    
    if identity.tier == zid_identity_core::IdentityTier::Managed {
        return Err(ApiError::InvalidRequest(
            "Rotation ceremony requires self-sovereign identity. Please upgrade your identity first.".to_string()
        ));
    }

    let new_identity_signing_public_key = parse_hex_32(&req.new_identity_signing_public_key)?;

    // Parse rotation signature (signature from current identity signing key)
    let rotation_signature_bytes = hex::decode(&req.rotation_signature)
        .map_err(|_| ApiError::InvalidRequest("Invalid rotation signature encoding".to_string()))?;

    // Get current identity to verify signature
    let identity = state
        .identity_service
        .get_identity(identity_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    verify_rotation_signature(
        identity_id,
        &identity.identity_signing_public_key,
        &new_identity_signing_public_key,
        &rotation_signature_bytes,
    )?;
    let approvals = parse_rotation_approvals(&req.approver_machine_ids, &req.approval_signatures)?;

    // Create rotation request
    let rotation_request = RotationRequest {
        identity_id,
        new_identity_signing_public_key,
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
        message: "Identity signing key rotated successfully".to_string(),
    }))
}

fn verify_rotation_signature(
    identity_id: Uuid,
    identity_signing_public_key: &[u8; 32],
    new_identity_signing_public_key: &[u8; 32],
    rotation_signature: &[u8],
) -> Result<(), ApiError> {
    if rotation_signature.len() != 64 {
        return Err(ApiError::InvalidRequest(
            "Rotation signature must be 64 bytes".to_string(),
        ));
    }

    let mut message = Vec::with_capacity(6 + 16 + 32);
    message.extend_from_slice(b"rotate");
    message.extend_from_slice(identity_id.as_bytes());
    message.extend_from_slice(new_identity_signing_public_key);

    let mut signature_array = [0u8; 64];
    signature_array.copy_from_slice(rotation_signature);

    zid_crypto::verify_signature(identity_signing_public_key, &message, &signature_array)
        .map_err(|_| ApiError::InvalidSignature)
}

fn parse_rotation_approvals(
    approver_machine_ids: &[Uuid],
    approval_signatures: &[String],
) -> Result<Vec<Approval>, ApiError> {
    if approver_machine_ids.len() != approval_signatures.len() {
        return Err(ApiError::InvalidRequest(
            "Number of approvers must match number of signatures".to_string(),
        ));
    }

    approval_signatures
        .iter()
        .enumerate()
        .map(|(i, sig_hex)| {
            let signature_bytes = hex::decode(sig_hex)
                .map_err(|_| ApiError::InvalidRequest("Invalid hex encoding".to_string()))?;

            Ok(Approval {
                machine_id: approver_machine_ids[i],
                signature: signature_bytes,
                timestamp: chrono::Utc::now().timestamp() as u64,
            })
        })
        .collect()
}
