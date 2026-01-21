//! Wallet-based authentication handler.

use axum::{extract::State, response::Json};
use std::sync::Arc;
use uuid::Uuid;
use zero_auth_identity_core::IdentityCore;
use zero_auth_methods::AuthMethods;
use zero_auth_sessions::SessionManager;

use crate::{
    error::{map_service_error, ApiError},
    state::AppState,
};

use super::auth::{LoginResponse, WalletLoginRequest};
use super::helpers::format_timestamp_rfc3339;

/// POST /v1/auth/login/wallet
pub async fn login_wallet(
    State(state): State<Arc<AppState>>,
    ctx: crate::request_context::RequestContext,
    Json(req): Json<WalletLoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    // Parse and validate signature
    let signature_bytes = parse_wallet_signature(&req.signature)?;

    // Validate message format
    validate_wallet_message(&req.message, &req.wallet_address)?;

    // Validate timestamp in message
    validate_message_timestamp(&req.message)?;

    // Verify EVM signature
    verify_evm_signature(&req.message, &signature_bytes, &req.wallet_address)?;

    // Authenticate with wallet service
    let auth_result = authenticate_wallet(&state, &req, &ctx, signature_bytes).await?;

    // Create session
    create_wallet_session(&state, &auth_result).await
}

/// Parse wallet signature from hex string
fn parse_wallet_signature(signature_hex: &str) -> Result<Vec<u8>, ApiError> {
    let signature_bytes = hex::decode(signature_hex)
        .map_err(|_| ApiError::InvalidRequest("Invalid signature".to_string()))?;

    // Ensure signature is exactly 65 bytes (r,s,v)
    if signature_bytes.len() != 65 {
        return Err(ApiError::InvalidRequest(format!(
            "Invalid signature length: expected 65 bytes, got {}",
            signature_bytes.len()
        )));
    }

    Ok(signature_bytes)
}

/// Validate the wallet authentication message format
fn validate_wallet_message(message: &str, wallet_address: &str) -> Result<(), ApiError> {
    // Standard format: "Sign in to zero-auth\nTimestamp: <unix_timestamp>\nWallet: <address>"
    if !message.contains("Sign in to zero-auth")
        || !message.contains("Timestamp:")
        || !message.contains(wallet_address)
    {
        return Err(ApiError::InvalidRequest(
            "Invalid message format. Expected standard auth message.".to_string(),
        ));
    }
    Ok(())
}

/// Validate timestamp in message is within acceptable range
fn validate_message_timestamp(message: &str) -> Result<(), ApiError> {
    let timestamp_str = message
        .lines()
        .find(|line| line.starts_with("Timestamp:"))
        .and_then(|line| line.strip_prefix("Timestamp:"))
        .map(|s| s.trim())
        .ok_or_else(|| ApiError::InvalidRequest("Missing timestamp in message".to_string()))?;

    let message_timestamp: u64 = timestamp_str
        .parse()
        .map_err(|_| ApiError::InvalidRequest("Invalid timestamp format".to_string()))?;

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("System time error")))?
        .as_secs();

    // Allow 60 seconds clock skew tolerance for future timestamps
    const TIME_TOLERANCE: u64 = 60;

    if message_timestamp > current_time + TIME_TOLERANCE {
        return Err(ApiError::InvalidRequest(
            "Message timestamp is in the future".to_string(),
        ));
    }

    if current_time > message_timestamp + 300 {
        return Err(ApiError::InvalidRequest(
            "Message timestamp expired (>5 minutes old)".to_string(),
        ));
    }

    Ok(())
}

/// Verify EVM signature and recovered address matches
fn verify_evm_signature(
    message: &str,
    signature_bytes: &[u8],
    expected_address: &str,
) -> Result<(), ApiError> {
    use zero_auth_methods::wallet::{build_eip191_message, keccak256, recover_address};

    let mut signature_array = [0u8; 65];
    signature_array.copy_from_slice(signature_bytes);

    // Build EIP-191 message and hash it
    let eip191_message = build_eip191_message(message);
    let message_hash = keccak256(eip191_message.as_bytes());

    // Recover address from signature
    let recovered_address = recover_address(&message_hash, &signature_array)
        .map_err(|e| ApiError::InvalidRequest(format!("Signature recovery failed: {}", e)))?;

    // Verify recovered address matches provided wallet address
    if recovered_address.to_lowercase() != expected_address.to_lowercase() {
        return Err(ApiError::InvalidRequest(format!(
            "Signature verification failed: expected {}, recovered {}",
            expected_address, recovered_address
        )));
    }

    Ok(())
}

/// Wallet authentication result
struct WalletAuthResult {
    identity_id: Uuid,
    machine_id: Uuid,
    namespace_id: Uuid,
    mfa_verified: bool,
}

/// Authenticate with wallet service
async fn authenticate_wallet(
    state: &Arc<AppState>,
    req: &WalletLoginRequest,
    ctx: &crate::request_context::RequestContext,
    signature_bytes: Vec<u8>,
) -> Result<WalletAuthResult, ApiError> {
    use zero_auth_methods::WalletSignature;

    let wallet_sig = WalletSignature {
        challenge_id: Uuid::nil(), // Wallet login uses message-based auth, not challenge-based
        wallet_address: req.wallet_address.clone(),
        signature: signature_bytes,
        mfa_code: None,
    };

    let auth_result = state
        .auth_service
        .authenticate_wallet(wallet_sig, ctx.ip_address.clone(), ctx.user_agent.clone())
        .await
        .map_err(|e| map_service_error(anyhow::anyhow!(e)))?;

    Ok(WalletAuthResult {
        identity_id: auth_result.identity_id,
        machine_id: auth_result.machine_id,
        namespace_id: auth_result.namespace_id,
        mfa_verified: auth_result.mfa_verified,
    })
}

/// Create session for authenticated wallet user
async fn create_wallet_session(
    state: &Arc<AppState>,
    auth_result: &WalletAuthResult,
) -> Result<Json<LoginResponse>, ApiError> {
    // Get machine key to extract capabilities
    let machine = state
        .identity_service
        .get_machine_key(auth_result.machine_id)
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
            auth_result.machine_id,
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
        machine_id: auth_result.machine_id,
        expires_at: {
            let now = chrono::Utc::now().timestamp();
            let expires_in = session.expires_in as i64;
            let expires_at = now
                .checked_add(expires_in)
                .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("Timestamp overflow")))?;
            format_timestamp_rfc3339(expires_at as u64)?
        },
        warning: None,
    }))
}
