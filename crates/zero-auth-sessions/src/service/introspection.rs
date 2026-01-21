//! Token introspection and validation logic.

use crate::{errors::*, types::*, EventPublisher};
use uuid::Uuid;
use zero_auth_identity_core::IdentityCore;
use zero_auth_storage::Storage;

use super::{base64_url_encode, SessionService};

impl<S: Storage, I: IdentityCore, E: EventPublisher> SessionService<S, I, E> {
    /// Introspect a token and return its status and claims
    pub(crate) async fn introspect_token_internal(
        &self,
        token: String,
        audience: Option<String>,
    ) -> Result<TokenIntrospection> {
        // Verify JWT signature
        let claims = match self.verify_jwt_internal(&token).await {
            Ok(claims) => claims,
            Err(_) => {
                return Ok(build_inactive_introspection());
            }
        };

        // Check audience if provided
        if let Some(aud) = &audience {
            if !claims.aud.contains(aud) {
                return Ok(build_inactive_introspection());
            }
        }

        // Parse and validate token context
        match self.validate_token_context(&claims).await {
            Ok(context) => Ok(build_active_introspection(claims, context)),
            Err(_) => Ok(build_inactive_introspection()),
        }
    }

    /// Validate the context of a token (identity, session, machine status)
    async fn validate_token_context(&self, claims: &TokenClaims) -> Result<TokenContext> {
        // Parse UUIDs from claims
        let identity_id = Uuid::parse_str(&claims.sub).map_err(|_| SessionError::InvalidToken)?;
        let session_id =
            Uuid::parse_str(&claims.session_id).map_err(|_| SessionError::InvalidToken)?;
        let machine_id =
            Uuid::parse_str(&claims.machine_id).map_err(|_| SessionError::InvalidToken)?;
        let namespace_id =
            Uuid::parse_str(&claims.namespace_id).map_err(|_| SessionError::InvalidToken)?;

        // Check identity status
        let identity = self.identity_core.get_identity(identity_id).await?;

        if identity.status != zero_auth_identity_core::IdentityStatus::Active {
            return Err(SessionError::IdentityFrozen);
        }

        // Check session validity
        let session = self.get_session_internal(session_id).await?;

        if session.revoked {
            return Err(SessionError::SessionRevoked {
                reason: "Session revoked".to_string(),
            });
        }

        // Check session expiration
        let now = current_timestamp();
        if session.expires_at < now {
            tracing::info!(
                session_id = %session_id,
                expires_at = session.expires_at,
                current_time = now,
                "Session expired"
            );
            return Err(SessionError::SessionExpired {
                session_id,
                expired_at: session.expires_at,
            });
        }

        // Check machine revocation
        let machine = self.identity_core.get_machine_key(machine_id).await?;

        if machine.revoked {
            return Err(SessionError::MachineRevoked);
        }

        // Check revocation epoch
        if claims.revocation_epoch < machine.epoch {
            return Err(SessionError::InvalidToken);
        }

        Ok(TokenContext {
            identity_id,
            machine_id,
            namespace_id,
            session_id,
        })
    }

    /// Get JWKS for token verification
    pub(crate) async fn get_jwks_internal(&self) -> Result<JwksResponse> {
        let keys = self.signing_keys.read().await;
        let mut jwks_keys = Vec::new();

        for (kid, signing_key) in keys.iter() {
            if matches!(signing_key.status, KeyStatus::Active | KeyStatus::Rotating) {
                jwks_keys.push(JsonWebKey {
                    kty: "OKP".to_string(),
                    use_: Some("sig".to_string()),
                    alg: Some("EdDSA".to_string()),
                    kid: Some(kid.clone()),
                    crv: "Ed25519".to_string(),
                    x: base64_url_encode(&signing_key.public_key),
                });
            }
        }

        Ok(JwksResponse { keys: jwks_keys })
    }
}

/// Context extracted from a validated token
struct TokenContext {
    identity_id: Uuid,
    machine_id: Uuid,
    namespace_id: Uuid,
    session_id: Uuid,
}

/// Build an inactive introspection response
fn build_inactive_introspection() -> TokenIntrospection {
    TokenIntrospection {
        active: false,
        scope: None,
        client_id: None,
        username: None,
        token_type: None,
        exp: None,
        iat: None,
        nbf: None,
        sub: None,
        aud: None,
        iss: None,
        jti: None,
        identity_id: Uuid::nil(),
        machine_id: Uuid::nil(),
        namespace_id: Uuid::nil(),
        session_id: Uuid::nil(),
        mfa_verified: false,
        capabilities: Vec::new(),
        scopes: Vec::new(),
        revocation_epoch: 0,
        issued_at: 0,
        expires_at: 0,
    }
}

/// Build an active introspection response from validated claims and context
fn build_active_introspection(claims: TokenClaims, context: TokenContext) -> TokenIntrospection {
    TokenIntrospection {
        active: true,
        scope: Some(claims.scope.join(" ")),
        client_id: Some(claims.machine_id.to_string()),
        username: None,
        token_type: Some("Bearer".to_string()),
        exp: Some(claims.exp),
        iat: Some(claims.iat),
        nbf: Some(claims.nbf),
        sub: Some(claims.sub.to_string()),
        aud: Some(claims.aud.clone()),
        iss: Some(claims.iss.clone()),
        jti: Some(claims.jti.clone()),
        identity_id: context.identity_id,
        machine_id: context.machine_id,
        namespace_id: context.namespace_id,
        session_id: context.session_id,
        mfa_verified: claims.mfa_verified,
        capabilities: claims.capabilities.clone(),
        scopes: claims.scope.clone(),
        revocation_epoch: claims.revocation_epoch,
        issued_at: claims.iat,
        expires_at: claims.exp,
    }
}
