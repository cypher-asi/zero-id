use crate::{Result, Session, SessionTokens, JwksResponse, TokenIntrospection};
use async_trait::async_trait;
use uuid::Uuid;

/// Session manager trait for session and token operations
#[async_trait]
pub trait SessionManager: Send + Sync {
    /// Create a new session and issue initial tokens
    async fn create_session(
        &self,
        identity_id: Uuid,
        machine_id: Uuid,
        namespace_id: Uuid,
        mfa_verified: bool,
        capabilities: Vec<String>,
        scope: Vec<String>,
    ) -> Result<SessionTokens>;

    /// Refresh a session using a refresh token
    async fn refresh_session(
        &self,
        refresh_token: String,
        session_id: Uuid,
        machine_id: Uuid,
    ) -> Result<SessionTokens>;

    /// Revoke a specific session
    async fn revoke_session(&self, session_id: Uuid) -> Result<()>;

    /// Revoke all sessions for an identity
    async fn revoke_all_sessions(&self, identity_id: Uuid) -> Result<()>;

    /// Revoke a token family (security event)
    async fn revoke_token_family(&self, token_family_id: Uuid) -> Result<()>;

    /// Get session information
    async fn get_session(&self, session_id: Uuid) -> Result<Session>;

    /// Verify and introspect a JWT token
    async fn introspect_token(&self, token: String, audience: Option<String>) -> Result<TokenIntrospection>;

    /// Get JWKS for public key distribution
    async fn get_jwks(&self) -> Result<JwksResponse>;

    /// Rotate JWT signing key (admin operation)
    async fn rotate_signing_key(&self) -> Result<String>;
}

/// Event publisher trait for integration with events subsystem
#[async_trait]
pub trait EventPublisher: Send + Sync {
    /// Publish a revocation event
    async fn publish_revocation_event(&self, event: crate::RevocationEvent) -> Result<()>;
}

/// No-op event publisher for testing
pub struct NoOpEventPublisher;

#[async_trait]
impl EventPublisher for NoOpEventPublisher {
    async fn publish_revocation_event(&self, _event: crate::RevocationEvent) -> Result<()> {
        Ok(())
    }
}
