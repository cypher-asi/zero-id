use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

/// API error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorDetails,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetails {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Application error type
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("Unauthorized")]
    Unauthorized,
    
    /// Forbidden access
    #[allow(dead_code)]
    #[error("Forbidden: {0}")]
    Forbidden(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Conflict: {0}")]
    Conflict(String),
    
    /// Rate limit exceeded
    #[allow(dead_code)]
    #[error("Rate limited")]
    RateLimited,
    
    #[error("Identity frozen")]
    IdentityFrozen,
    
    #[error("Machine revoked")]
    MachineRevoked,
    
    /// MFA verification required
    #[allow(dead_code)]
    #[error("MFA required")]
    MfaRequired,
    
    /// Challenge has expired
    #[allow(dead_code)]
    #[error("Challenge expired")]
    ChallengeExpired,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Internal server error")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message, details) = match self {
            ApiError::InvalidRequest(msg) => (
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                msg,
                None,
            ),
            ApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Missing or invalid credentials".to_string(),
                None,
            ),
            ApiError::Forbidden(msg) => (
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                msg,
                None,
            ),
            ApiError::NotFound(msg) => (
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                msg,
                None,
            ),
            ApiError::Conflict(msg) => (
                StatusCode::CONFLICT,
                "CONFLICT",
                msg,
                None,
            ),
            ApiError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMITED",
                "Too many requests".to_string(),
                None,
            ),
            ApiError::IdentityFrozen => (
                StatusCode::FORBIDDEN,
                "IDENTITY_FROZEN",
                "Identity is frozen. Contact support to unfreeze.".to_string(),
                None,
            ),
            ApiError::MachineRevoked => (
                StatusCode::FORBIDDEN,
                "MACHINE_REVOKED",
                "Machine key has been revoked".to_string(),
                None,
            ),
            ApiError::MfaRequired => (
                StatusCode::FORBIDDEN,
                "MFA_REQUIRED",
                "MFA verification required".to_string(),
                None,
            ),
            ApiError::ChallengeExpired => (
                StatusCode::BAD_REQUEST,
                "CHALLENGE_EXPIRED",
                "Challenge has expired".to_string(),
                None,
            ),
            ApiError::InvalidSignature => (
                StatusCode::BAD_REQUEST,
                "INVALID_SIGNATURE",
                "Cryptographic signature is invalid".to_string(),
                None,
            ),
            ApiError::Internal(err) => {
                tracing::error!("Internal error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "An internal error occurred".to_string(),
                    None,
                )
            }
        };

        let body = Json(ErrorResponse {
            error: ErrorDetails {
                code: code.to_string(),
                message,
                details,
            },
        });

        (status, body).into_response()
    }
}

/// Helper to convert service errors to API errors
pub fn map_service_error(error: anyhow::Error) -> ApiError {
    let error_str = error.to_string();
    
    if error_str.contains("not found") {
        ApiError::NotFound(error_str)
    } else if error_str.contains("already exists") {
        ApiError::Conflict(error_str)
    } else if error_str.contains("frozen") {
        ApiError::IdentityFrozen
    } else if error_str.contains("revoked") {
        ApiError::MachineRevoked
    } else if error_str.contains("signature") {
        ApiError::InvalidSignature
    } else {
        ApiError::Internal(error)
    }
}
