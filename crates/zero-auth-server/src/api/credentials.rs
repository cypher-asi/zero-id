use axum::{extract::Path, extract::State, response::Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zero_auth_methods::AuthMethods;

use crate::{
    api::helpers::{hash_for_log, parse_oauth_provider},
    error::{map_service_error, ApiError},
    extractors::AuthenticatedUser,
    state::AppState,
};

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct AddEmailCredentialRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AddCredentialResponse {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct OAuthInitiateResponse {
    pub authorization_url: String,
    pub state: String,
}

#[derive(Debug, Deserialize)]
pub struct OAuthCompleteRequest {
    pub code: String,
    pub state: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /v1/credentials/email
/// Add an email/password credential to the authenticated user's identity
pub async fn add_email_credential(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(req): Json<AddEmailCredentialRequest>,
) -> Result<Json<AddCredentialResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;

    tracing::info!(
        identity_id = %identity_id,
        email_hash = %hash_for_log(&req.email),
        "Adding email credential"
    );

    // Attach email credential
    state
        .auth_service
        .attach_email_credential(identity_id, req.email.clone(), req.password)
        .await
        .map_err(|e| {
            tracing::warn!(
                identity_id = %identity_id,
                email_hash = %hash_for_log(&req.email),
                error = %e,
                "Failed to add email credential"
            );
            map_service_error(anyhow::anyhow!(e))
        })?;

    tracing::info!(
        identity_id = %identity_id,
        email_hash = %hash_for_log(&req.email),
        "Email credential added successfully"
    );

    Ok(Json(AddCredentialResponse {
        message: format!("Email credential '{}' added successfully", req.email),
    }))
}

/// POST /v1/credentials/oauth/:provider
/// Initiate OAuth link flow for the authenticated user's identity
pub async fn initiate_oauth_link(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Path(provider_str): Path<String>,
) -> Result<Json<OAuthInitiateResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;
    let provider = parse_oauth_provider(&provider_str)?;

    let response = state
        .auth_service
        .oauth_initiate(identity_id, provider)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(OAuthInitiateResponse {
        authorization_url: response.auth_url,
        state: response.state,
    }))
}

/// POST /v1/credentials/oauth/:provider/callback
/// Complete OAuth link flow for the authenticated user's identity
pub async fn complete_oauth_link(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Path(provider_str): Path<String>,
    Json(req): Json<OAuthCompleteRequest>,
) -> Result<Json<AddCredentialResponse>, ApiError> {
    let identity_id = auth.claims.identity_id()?;
    let provider = parse_oauth_provider(&provider_str)?;

    let oauth_request = zero_auth_methods::OAuthCompleteRequest {
        provider,
        code: req.code,
        state: req.state,
    };

    state
        .auth_service
        .oauth_complete(identity_id, oauth_request)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(AddCredentialResponse {
        message: "OAuth credential linked successfully".to_string(),
    }))
}
