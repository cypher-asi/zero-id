use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use std::sync::Arc;
use uuid::Uuid;
use zero_auth_sessions::SessionManager;

use crate::{error::ApiError, state::AppState};

/// JWT claims extracted from Authorization header
///
/// These claims are extracted from properly verified JWT tokens
/// and can be used for authorization decisions in API handlers.
#[derive(Debug, Clone)]
pub struct JwtClaims {
    pub sub: String,
    pub machine_id: String,
    pub mfa_verified: bool,
}

impl JwtClaims {
    /// Parse identity ID from token claims
    pub fn identity_id(&self) -> Result<Uuid, ApiError> {
        Uuid::parse_str(&self.sub)
            .map_err(|_| ApiError::InvalidRequest("Invalid identity_id in token".to_string()))
    }

    /// Parse machine ID from token claims
    pub fn machine_id(&self) -> Result<Uuid, ApiError> {
        Uuid::parse_str(&self.machine_id)
            .map_err(|_| ApiError::InvalidRequest("Invalid machine_id in token".to_string()))
    }

    /// Check if MFA is verified (for operations requiring MFA)
    pub fn require_mfa(&self) -> Result<(), ApiError> {
        if !self.mfa_verified {
            return Err(ApiError::InvalidRequest(
                "MFA verification required for this operation".to_string(),
            ));
        }
        Ok(())
    }
}

/// Extractor for authenticated requests
///
/// This extractor properly verifies JWT signatures using the session service
/// and validates revocation epochs to ensure tokens are still valid.
pub struct AuthenticatedUser {
    pub claims: JwtClaims,
}

#[async_trait]
impl FromRequestParts<Arc<AppState>> for AuthenticatedUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
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

        // CRITICAL: Use session service to properly verify JWT signature
        let introspection = state
            .session_service
            .introspect_token(token.to_string(), None)
            .await
            .map_err(|e| {
                tracing::warn!("Token introspection failed: {}", e);
                ApiError::Unauthorized
            })?;

        // Check if token is active
        if !introspection.active {
            tracing::warn!("Token is not active");
            return Err(ApiError::Unauthorized);
        }

        // Convert introspection to claims format
        // Note: Revocation epoch validation already performed in introspect_token
        let claims = JwtClaims {
            sub: introspection.identity_id.to_string(),
            machine_id: introspection.machine_id.to_string(),
            mfa_verified: introspection.mfa_verified,
        };

        Ok(AuthenticatedUser { claims })
    }
}
