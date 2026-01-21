use axum::{extract::State, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use zero_auth_sessions::SessionManager;

use crate::{
    error::{map_service_error, ApiError},
    extractors::AuthenticatedUser,
    state::AppState,
};

use super::helpers::format_timestamp_rfc3339;

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct RefreshSessionRequest {
    pub refresh_token: String,
    pub session_id: Uuid,
    pub machine_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct RefreshSessionResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct RevokeSessionRequest {
    pub session_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct IntrospectTokenRequest {
    pub token: String,
    /// Operation type for fine-grained authorization
    pub operation_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IntrospectTokenResponse {
    pub active: bool,
    pub identity_id: Option<Uuid>,
    pub machine_id: Option<Uuid>,
    pub namespace_id: Option<Uuid>,
    pub mfa_verified: Option<bool>,
    pub capabilities: Option<Vec<String>>,
    pub scope: Option<Vec<String>>,
    pub revocation_epoch: Option<u64>,
    pub exp: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct JwksResponse {
    pub keys: Vec<JwkKey>,
}

#[derive(Debug, Serialize)]
pub struct JwkKey {
    pub kty: String,
    pub kid: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub key_use: String,
    pub crv: String,
    pub x: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /v1/auth/refresh
pub async fn refresh_session(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshSessionRequest>,
) -> Result<Json<RefreshSessionResponse>, ApiError> {
    // Refresh the session
    let result = state
        .session_service
        .refresh_session(req.refresh_token, req.session_id, req.machine_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    let expires_at_ts = chrono::Utc::now().timestamp() as u64 + result.expires_in;

    Ok(Json(RefreshSessionResponse {
        access_token: result.access_token,
        refresh_token: result.refresh_token,
        expires_at: format_timestamp_rfc3339(expires_at_ts)?,
    }))
}

/// POST /v1/session/revoke
pub async fn revoke_session(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<RevokeSessionRequest>,
) -> Result<StatusCode, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    let session = state
        .session_service
        .get_session(req.session_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    if session.identity_id != identity_id {
        return Err(ApiError::Forbidden(
            "Session does not belong to authenticated identity".to_string(),
        ));
    }

    // Revoke the session
    state
        .session_service
        .revoke_session(req.session_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /v1/session/revoke-all
pub async fn revoke_all_sessions(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
) -> Result<StatusCode, ApiError> {
    // Revoking all sessions is a high-risk operation - require MFA
    auth.claims.require_mfa()?;

    let identity_id = auth.claims.identity_id()?;

    // Revoke all sessions for the identity
    state
        .session_service
        .revoke_all_sessions(identity_id)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /v1/auth/introspect
pub async fn introspect_token(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<IntrospectTokenRequest>,
) -> Result<Json<IntrospectTokenResponse>, ApiError> {
    let requester_identity_id = auth.claims.identity_id()?;

    // Introspect the token using session service
    match state
        .session_service
        .introspect_token(req.token.clone(), None)
        .await
    {
        Ok(result) => {
            if result.active && result.identity_id != requester_identity_id {
                return Err(ApiError::Forbidden(
                    "Token does not belong to authenticated identity".to_string(),
                ));
            }

            // If operation_type is provided, perform additional authorization checks
            if let Some(op_type) = req.operation_type {
                // Check if operation requires specific capabilities
                let required_capability = match op_type.as_str() {
                    "vault:read" => Some("VAULT_OPERATIONS"),
                    "vault:write" => Some("VAULT_OPERATIONS"),
                    "sign" => Some("SIGN"),
                    "encrypt" => Some("ENCRYPT"),
                    "svk_unwrap" => Some("SVK_UNWRAP"),
                    "mls_messaging" => Some("MLS_MESSAGING"),
                    _ => None,
                };

                if let Some(cap) = required_capability {
                    let has_capability = result.capabilities.iter().any(|c| c == cap);

                    if !has_capability {
                        // Token is active but doesn't have required capability
                        return Ok(Json(IntrospectTokenResponse {
                            active: false, // Set to false since insufficient privileges
                            identity_id: Some(result.identity_id),
                            machine_id: Some(result.machine_id),
                            namespace_id: Some(result.namespace_id),
                            mfa_verified: Some(result.mfa_verified),
                            capabilities: Some(result.capabilities.clone()),
                            scope: Some(result.scopes.clone()),
                            revocation_epoch: Some(result.revocation_epoch),
                            exp: Some(result.expires_at),
                        }));
                    }
                }
            }

            // Return full introspection result
            Ok(Json(IntrospectTokenResponse {
                active: result.active,
                identity_id: Some(result.identity_id),
                machine_id: Some(result.machine_id),
                namespace_id: Some(result.namespace_id),
                mfa_verified: Some(result.mfa_verified),
                capabilities: Some(result.capabilities),
                scope: Some(result.scopes),
                revocation_epoch: Some(result.revocation_epoch),
                exp: Some(result.expires_at),
            }))
        }
        Err(_) => {
            // Token is invalid or expired
            Ok(Json(IntrospectTokenResponse {
                active: false,
                identity_id: None,
                machine_id: None,
                namespace_id: None,
                mfa_verified: None,
                capabilities: None,
                scope: None,
                revocation_epoch: None,
                exp: None,
            }))
        }
    }
}

/// GET /.well-known/jwks.json
pub async fn jwks_endpoint(
    State(state): State<Arc<AppState>>,
) -> Result<Json<JwksResponse>, ApiError> {
    // Get JWKS from session service
    let jwks = state
        .session_service
        .get_jwks()
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    // Convert to response format
    let keys = jwks
        .keys
        .into_iter()
        .map(|key| JwkKey {
            kty: key.kty,
            kid: key.kid.unwrap_or_default(),
            alg: key.alg.unwrap_or_else(|| "EdDSA".to_string()),
            key_use: key.use_.unwrap_or_else(|| "sig".to_string()),
            crv: key.crv,
            x: key.x,
        })
        .collect();

    Ok(Json(JwksResponse { keys }))
}
