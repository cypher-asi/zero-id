use axum::{
    extract::{Path, Query, State},
    response::Json,
};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use zero_auth_identity_core::IdentityCore;
use zero_auth_methods::{
    AuthMethods, ChallengeRequest, ChallengeResponse as AuthChallengeResponse, EmailAuthRequest,
    OAuthCompleteRequest as AuthOAuthCompleteRequest,
};
use zero_auth_sessions::SessionManager;

use super::helpers::format_timestamp_rfc3339;
use crate::{
    api::helpers::{hash_for_log, parse_oauth_provider},
    error::{map_service_error, ApiError},
    state::AppState,
};

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ChallengeQuery {
    pub machine_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub challenge_id: Uuid,
    pub challenge: String, // base64
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct MachineLoginRequest {
    pub challenge_id: Uuid,
    pub machine_id: Uuid,
    pub signature: String, // hex
}

#[derive(Debug, Deserialize)]
pub struct EmailLoginRequest {
    pub email: String,
    pub password: String,
    pub machine_id: Option<Uuid>,
    pub mfa_code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WalletLoginRequest {
    pub wallet_address: String, // hex
    pub signature: String,      // hex
    /// Message that was signed (should be challenge or standard auth message)
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub session_id: Uuid,
    pub machine_id: Uuid,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
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

/// GET /v1/auth/challenge
pub async fn get_challenge(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ChallengeQuery>,
) -> Result<Json<ChallengeResponse>, ApiError> {
    let request = ChallengeRequest {
        machine_id: query.machine_id,
        purpose: Some("authentication".to_string()),
    };

    let challenge = state
        .auth_service
        .create_challenge(request)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    // Serialize the challenge to canonical form
    let challenge_bytes =
        serde_json::to_vec(&challenge).map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;

    Ok(Json(ChallengeResponse {
        challenge_id: challenge.challenge_id,
        challenge: BASE64_STANDARD.encode(&challenge_bytes),
        expires_at: format_timestamp_rfc3339(challenge.exp)?,
    }))
}

/// POST /v1/auth/login/machine
pub async fn login_machine(
    State(state): State<Arc<AppState>>,
    ctx: crate::request_context::RequestContext,
    Json(req): Json<MachineLoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    // Log authentication attempt with request context
    tracing::info!(
        ip = %ctx.ip_address,
        user_agent = %ctx.user_agent,
        machine_id = %req.machine_id,
        "Machine authentication attempt"
    );

    // Parse signature
    let signature_bytes = hex::decode(&req.signature)
        .map_err(|_| ApiError::InvalidRequest("Invalid hex encoding".to_string()))?;

    // Authenticate
    let challenge_response = AuthChallengeResponse {
        challenge_id: req.challenge_id,
        machine_id: req.machine_id,
        signature: signature_bytes,
        mfa_code: None,
    };

    let auth_result = state
        .auth_service
        .authenticate_machine(
            challenge_response,
            ctx.ip_address.clone(),
            ctx.user_agent.clone(),
        )
        .await
        .map_err(|e| {
            tracing::warn!(
                ip = %ctx.ip_address,
                machine_id = %req.machine_id,
                error = %e,
                "Machine authentication failed"
            );
            map_service_error(anyhow::anyhow!(e))
        })?;

    // Get machine key to extract capabilities
    let machine = state
        .identity_service
        .get_machine_key(req.machine_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get machine key");
            map_service_error(anyhow::anyhow!(e))
        })?;

    // Create session with machine capabilities
    let session = state
        .session_service
        .create_session(
            auth_result.identity_id,
            req.machine_id,
            auth_result.namespace_id,
            auth_result.mfa_verified,
            machine.capabilities.to_string_vec(),
            vec!["default".to_string()], // Default scope
        )
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(LoginResponse {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        session_id: session.session_id,
        machine_id: req.machine_id,
        expires_at: format_expires_at(session.expires_in)?,
        warning: None,
    }))
}

/// POST /v1/auth/login/email
pub async fn login_email(
    State(state): State<Arc<AppState>>,
    ctx: crate::request_context::RequestContext,
    Json(req): Json<EmailLoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    // Log authentication attempt with request context
    tracing::info!(
        ip = %ctx.ip_address,
        user_agent = %ctx.user_agent,
        email_hash = %hash_for_log(&req.email),
        "Email authentication attempt"
    );

    // Authenticate with email+password
    let email_request = EmailAuthRequest {
        email: req.email.clone(),
        password: req.password,
        machine_id: req.machine_id,
        mfa_code: req.mfa_code,
    };

    let auth_result = state
        .auth_service
        .authenticate_email(
            email_request,
            ctx.ip_address.clone(),
            ctx.user_agent.clone(),
        )
        .await
        .map_err(|e| {
            tracing::warn!(
                ip = %ctx.ip_address,
                email_hash = %hash_for_log(&req.email),
                error = %e,
                "Email authentication failed"
            );
            map_service_error(anyhow::anyhow!(e))
        })?;

    let machine_id = auth_result.machine_id;
    let warning = auth_result.warning.clone();

    // Get machine key to extract capabilities
    let machine = state
        .identity_service
        .get_machine_key(machine_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get machine key");
            map_service_error(anyhow::anyhow!(e))
        })?;

    // Create session with machine capabilities
    let session = state
        .session_service
        .create_session(
            auth_result.identity_id,
            machine_id,
            auth_result.namespace_id,
            auth_result.mfa_verified,
            machine.capabilities.to_string_vec(),
            vec!["default".to_string()], // Default scope
        )
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(LoginResponse {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        session_id: session.session_id,
        machine_id,
        expires_at: format_expires_at(session.expires_in)?,
        warning,
    }))
}

/// GET /v1/auth/oauth/:provider
pub async fn oauth_initiate(
    State(state): State<Arc<AppState>>,
    Path(provider_str): Path<String>,
) -> Result<Json<OAuthInitiateResponse>, ApiError> {
    // Parse provider
    let provider = parse_oauth_provider(&provider_str)?;

    // Initiate OAuth flow
    let response = state
        .auth_service
        .oauth_initiate_login(provider)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(OAuthInitiateResponse {
        authorization_url: response.auth_url,
        state: response.state,
    }))
}

/// POST /v1/auth/oauth/:provider/callback
pub async fn oauth_complete(
    State(state): State<Arc<AppState>>,
    ctx: crate::request_context::RequestContext,
    Path(provider_str): Path<String>,
    Json(req): Json<OAuthCompleteRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    // Parse provider
    let provider = parse_oauth_provider(&provider_str)?;

    // Complete OAuth flow for authentication
    let oauth_request = AuthOAuthCompleteRequest {
        provider,
        code: req.code,
        state: req.state,
    };

    let auth_result = state
        .auth_service
        .authenticate_oauth(
            oauth_request,
            ctx.ip_address.clone(),
            ctx.user_agent.clone(),
        )
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    let machine_id = auth_result.machine_id;
    let warning = auth_result.warning.clone();

    // Get machine key to extract capabilities
    let machine = state
        .identity_service
        .get_machine_key(machine_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get machine key");
            map_service_error(anyhow::anyhow!(e))
        })?;

    // Create session with machine capabilities
    let session = state
        .session_service
        .create_session(
            auth_result.identity_id,
            machine_id,
            auth_result.namespace_id,
            auth_result.mfa_verified,
            machine.capabilities.to_string_vec(),
            vec!["default".to_string()], // Default scope
        )
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(LoginResponse {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        session_id: session.session_id,
        machine_id,
        expires_at: format_expires_at(session.expires_in)?,
        warning,
    }))
}

/// Format expires_at timestamp from expires_in seconds
fn format_expires_at(expires_in: u64) -> Result<String, ApiError> {
    let now = chrono::Utc::now().timestamp();
    let expires_in = expires_in as i64;
    let expires_at = now
        .checked_add(expires_in)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("Timestamp overflow")))?;

    format_timestamp_rfc3339(expires_at as u64)
}
