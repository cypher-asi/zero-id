use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zero_auth_auth_methods::AuthMethods;

use crate::{error::{ApiError, map_service_error}, extractors::AuthenticatedUser, state::AppState};

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct SetupMfaRequest {
    pub encrypted_totp_secret: EncryptedSecret,
    /// Pre-hashed backup codes (for future client-side hashing support)
    #[allow(dead_code)]
    pub backup_code_hashes: Vec<String>,
    pub verification_code: String,
}

#[derive(Debug, Deserialize)]
pub struct EncryptedSecret {
    pub ciphertext: String, // hex
    pub nonce: String, // hex (24 bytes)
    pub algorithm: String, // "xchacha20poly1305"
}

#[derive(Debug, Serialize)]
pub struct SetupMfaResponse {
    pub mfa_enabled: bool,
    pub enabled_at: String,
}

#[derive(Debug, Deserialize)]
pub struct DisableMfaRequest {
    pub mfa_code: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /v1/mfa/setup
pub async fn setup_mfa(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<SetupMfaRequest>,
) -> Result<Json<SetupMfaResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    // Validate algorithm
    if req.encrypted_totp_secret.algorithm != "xchacha20poly1305" {
        return Err(ApiError::InvalidRequest(
            "Only xchacha20poly1305 encryption is supported".to_string(),
        ));
    }

    // Parse ciphertext and nonce
    let _ciphertext = hex::decode(&req.encrypted_totp_secret.ciphertext)
        .map_err(|_| ApiError::InvalidRequest("Invalid ciphertext encoding".to_string()))?;
    
    let nonce_bytes = hex::decode(&req.encrypted_totp_secret.nonce)
        .map_err(|_| ApiError::InvalidRequest("Invalid nonce encoding".to_string()))?;
    
    if nonce_bytes.len() != 24 {
        return Err(ApiError::InvalidRequest("Nonce must be 24 bytes".to_string()));
    }
    
    let mut _nonce = [0u8; 24];
    _nonce.copy_from_slice(&nonce_bytes);

    // Setup MFA
    let _mfa_setup = state
        .auth_service
        .setup_mfa(identity_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    // Enable MFA with verification code
    state
        .auth_service
        .enable_mfa(identity_id, req.verification_code)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(SetupMfaResponse {
        mfa_enabled: true,
        enabled_at: chrono::Utc::now().to_rfc3339(),
    }))
}

/// DELETE /v1/mfa
pub async fn disable_mfa(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<DisableMfaRequest>,
) -> Result<StatusCode, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    // Disable MFA (requires verification)
    state
        .auth_service
        .disable_mfa(identity_id, req.mfa_code)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(StatusCode::NO_CONTENT)
}
