use axum::{
    extract::{Path, Query, State},
    response::Json,
};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use zero_auth_auth_methods::{AuthMethods, ChallengeRequest, ChallengeResponse as AuthChallengeResponse, EmailAuthRequest, OAuthCompleteRequest as AuthOAuthCompleteRequest};
use zero_auth_sessions::SessionManager;

use crate::{error::{ApiError, map_service_error}, state::AppState};

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
    pub signature: String, // hex
    /// Message that was signed (for future use)
    #[allow(dead_code)]
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
    let challenge_bytes = serde_json::to_vec(&challenge)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;

    Ok(Json(ChallengeResponse {
        challenge_id: challenge.challenge_id,
        challenge: base64::prelude::BASE64_STANDARD.encode(&challenge_bytes),
        expires_at: chrono::DateTime::from_timestamp(challenge.exp as i64, 0)
            .unwrap()
            .to_rfc3339(),
    }))
}

/// POST /v1/auth/login/machine
pub async fn login_machine(
    State(state): State<Arc<AppState>>,
    Json(req): Json<MachineLoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
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
        .authenticate_machine(challenge_response)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    // Create session
    let session = state
        .session_service
        .create_session(
            auth_result.identity_id,
            req.machine_id,
            auth_result.namespace_id,
            auth_result.mfa_verified,
            vec![], // TODO: Convert capabilities to strings
            vec![], // Default empty scope
        )
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(LoginResponse {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        session_id: session.session_id,
        machine_id: req.machine_id,
        expires_at: chrono::DateTime::from_timestamp((session.expires_in + chrono::Utc::now().timestamp() as u64) as i64, 0)
            .unwrap()
            .to_rfc3339(),
        warning: None,
    }))
}

/// POST /v1/auth/login/email
pub async fn login_email(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EmailLoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    // Authenticate with email+password
    let email_request = EmailAuthRequest {
        email: req.email,
        password: req.password,
        machine_id: req.machine_id,
        mfa_code: req.mfa_code,
    };

    let auth_result = state
        .auth_service
        .authenticate_email(email_request)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    let machine_id = auth_result.machine_id;
    let warning = auth_result.warning.clone();

    // Create session
    let session = state
        .session_service
        .create_session(
            auth_result.identity_id,
            machine_id,
            auth_result.namespace_id,
            auth_result.mfa_verified,
            vec![], // TODO: Convert capabilities to strings
            vec![], // Default empty scope
        )
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(LoginResponse {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        session_id: session.session_id,
        machine_id,
        expires_at: chrono::DateTime::from_timestamp((session.expires_in + chrono::Utc::now().timestamp() as u64) as i64, 0)
            .unwrap()
            .to_rfc3339(),
        warning,
    }))
}

/// POST /v1/auth/login/wallet
pub async fn login_wallet(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WalletLoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    // Parse signature
    let signature_bytes = hex::decode(&req.signature)
        .map_err(|_| ApiError::InvalidRequest("Invalid signature".to_string()))?;

    // Create wallet signature request
    use zero_auth_auth_methods::WalletSignature;
    let wallet_sig = WalletSignature {
        challenge_id: Uuid::new_v4(), // TODO: Should come from challenge
        wallet_address: req.wallet_address.clone(),
        signature: signature_bytes,
        mfa_code: None,
    };

    // Authenticate
    let auth_result = state
        .auth_service
        .authenticate_wallet(wallet_sig)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    let machine_id = auth_result.machine_id;

    let session = state
        .session_service
        .create_session(
            auth_result.identity_id,
            machine_id,
            auth_result.namespace_id,
            auth_result.mfa_verified,
            vec![], // TODO: Convert capabilities to strings
            vec![], // Default empty scope
        )
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(LoginResponse {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        session_id: session.session_id,
        machine_id,
        expires_at: chrono::DateTime::from_timestamp((session.expires_in + chrono::Utc::now().timestamp() as u64) as i64, 0)
            .unwrap()
            .to_rfc3339(),
        warning: None,
    }))
}

/// GET /v1/auth/oauth/:provider
pub async fn oauth_initiate(
    State(state): State<Arc<AppState>>,
    Path(provider_str): Path<String>,
) -> Result<Json<OAuthInitiateResponse>, ApiError> {
    // Parse provider
    let provider = parse_oauth_provider(&provider_str)?;

    // For now, use a dummy identity_id for OAuth initiation
    // In production, this should come from session or be handled differently
    let identity_id = Uuid::nil();

    // Initiate OAuth flow
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

/// POST /v1/auth/oauth/:provider/callback
pub async fn oauth_complete(
    State(state): State<Arc<AppState>>,
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
        .authenticate_oauth(oauth_request)
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    let machine_id = auth_result.machine_id;
    let warning = auth_result.warning.clone();

    // Create session
    let session = state
        .session_service
        .create_session(
            auth_result.identity_id,
            machine_id,
            auth_result.namespace_id,
            auth_result.mfa_verified,
            vec![], // TODO: Convert capabilities to strings
            vec![], // Default empty scope
        )
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(Json(LoginResponse {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        session_id: session.session_id,
        machine_id,
        expires_at: chrono::DateTime::from_timestamp((session.expires_in + chrono::Utc::now().timestamp() as u64) as i64, 0)
            .unwrap()
            .to_rfc3339(),
        warning,
    }))
}

// ============================================================================
// Helper Functions
// ============================================================================

fn parse_oauth_provider(provider_str: &str) -> Result<zero_auth_auth_methods::OAuthProvider, ApiError> {
    use zero_auth_auth_methods::OAuthProvider;
    match provider_str.to_lowercase().as_str() {
        "google" => Ok(OAuthProvider::Google),
        "x" | "twitter" => Ok(OAuthProvider::X),
        "epic" => Ok(OAuthProvider::EpicGames),
        _ => Err(ApiError::InvalidRequest(format!("Unknown OAuth provider: {}", provider_str))),
    }
}
