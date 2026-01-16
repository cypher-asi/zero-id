use axum::{
    async_trait,
    extract::FromRequestParts,
    http::request::Parts,
};
use base64::{Engine as _, engine::general_purpose};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiError;

/// JWT claims extracted from Authorization header
#[derive(Debug, Clone, Deserialize)]
pub struct JwtClaims {
    pub sub: String,          // identity_id
    pub machine_id: String,
    /// Namespace ID (for future multi-tenancy support)
    #[allow(dead_code)]
    pub namespace_id: String,
    /// Whether MFA was verified (for future fine-grained auth)
    #[allow(dead_code)]
    pub mfa_verified: bool,
    /// Capabilities (for future capability-based access control)
    #[allow(dead_code)]
    pub capabilities: Vec<String>,
    /// OAuth-style scopes (for future scope-based authorization)
    #[allow(dead_code)]
    pub scope: Vec<String>,
    /// Revocation epoch for token invalidation (for future use)
    #[allow(dead_code)]
    pub revocation_epoch: u64,
    /// Issued at timestamp (for future token validation)
    #[allow(dead_code)]
    pub iat: u64,
    /// Expiration timestamp (for future token validation)
    #[allow(dead_code)]
    pub exp: u64,
}

impl JwtClaims {
    pub fn identity_id(&self) -> Result<Uuid, ApiError> {
        Uuid::parse_str(&self.sub)
            .map_err(|_| ApiError::InvalidRequest("Invalid identity_id in token".to_string()))
    }

    pub fn machine_id(&self) -> Result<Uuid, ApiError> {
        Uuid::parse_str(&self.machine_id)
            .map_err(|_| ApiError::InvalidRequest("Invalid machine_id in token".to_string()))
    }
    
    /// Parse namespace ID from token (for future use)
    #[allow(dead_code)]
    pub fn namespace_id(&self) -> Result<Uuid, ApiError> {
        Uuid::parse_str(&self.namespace_id)
            .map_err(|_| ApiError::InvalidRequest("Invalid namespace_id in token".to_string()))
    }
}

/// Extractor for authenticated requests
pub struct AuthenticatedUser {
    pub claims: JwtClaims,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract Authorization header
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;

        // Parse Bearer token
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(ApiError::Unauthorized)?;

        // For now, we'll do basic JWT parsing without validation
        // Full validation will be done via the session service
        let claims = parse_jwt_claims(token)?;

        Ok(AuthenticatedUser { claims })
    }
}

/// Parse JWT claims without verification (verification done by session service)
fn parse_jwt_claims(token: &str) -> Result<JwtClaims, ApiError> {
    // Split JWT into parts
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(ApiError::Unauthorized);
    }

    // Decode payload (second part)
    let payload = general_purpose::URL_SAFE_NO_PAD.decode(parts[1])
        .map_err(|_| ApiError::Unauthorized)?;

    // Parse claims
    serde_json::from_slice(&payload)
        .map_err(|_| ApiError::Unauthorized)
}
