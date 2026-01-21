//! Session lifecycle operations: create, refresh, revoke.

use crate::{errors::*, types::*, EventPublisher};
use uuid::Uuid;
use zero_auth_identity_core::IdentityCore;
use zero_auth_storage::{column_families::*, Storage};

use super::{sha256, SessionService};

impl<S: Storage, I: IdentityCore, E: EventPublisher> SessionService<S, I, E> {
    /// Create a new session for an authenticated identity
    pub(crate) async fn create_session_internal(
        &self,
        identity_id: Uuid,
        machine_id: Uuid,
        namespace_id: Uuid,
        mfa_verified: bool,
        capabilities: Vec<String>,
        scope: Vec<String>,
    ) -> Result<SessionTokens> {
        // Check identity status
        let identity = self.identity_core.get_identity(identity_id).await?;

        if identity.status == zero_auth_identity_core::IdentityStatus::Frozen {
            return Err(SessionError::IdentityFrozen);
        }

        // Check machine status
        let machine = self.identity_core.get_machine_key(machine_id).await?;

        if machine.revoked {
            return Err(SessionError::MachineRevoked);
        }

        // Create session
        let session_id = Uuid::new_v4();
        let token_family_id = Uuid::new_v4();

        let session = Session {
            session_id,
            identity_id,
            machine_id,
            namespace_id,
            token_family_id,
            created_at: current_timestamp(),
            expires_at: current_timestamp() + self.refresh_token_ttl,
            last_activity_at: current_timestamp(),
            revoked: false,
            revoked_at: None,
            revoked_reason: None,
        };

        // Store session
        self.storage
            .put(CF_SESSIONS, session_id.as_bytes(), &session)
            .await?;

        // Index by identity
        let identity_index_key = {
            let mut key = Vec::with_capacity(32);
            key.extend_from_slice(identity_id.as_bytes());
            key.extend_from_slice(session_id.as_bytes());
            key
        };

        let empty_value: Vec<u8> = vec![];
        self.storage
            .put(CF_SESSIONS_BY_IDENTITY, &identity_index_key, &empty_value)
            .await?;

        // Generate tokens
        let access_token = self
            .issue_access_token(&session, mfa_verified, capabilities, scope)
            .await?;

        let refresh_token = self
            .generate_refresh_token(session_id, machine_id, token_family_id, 1)
            .await?;

        Ok(SessionTokens {
            access_token,
            refresh_token,
            session_id,
            expires_in: self.access_token_ttl,
            token_type: "Bearer".to_string(),
        })
    }

    /// Refresh a session using a refresh token
    pub(crate) async fn refresh_session_internal(
        &self,
        refresh_token: String,
        session_id: Uuid,
        machine_id: Uuid,
    ) -> Result<SessionTokens> {
        // Step 1: Hash token for lookup
        let token_hash = sha256(refresh_token.as_bytes());

        // Step 2: Get and validate refresh token record
        let mut token_record = self.get_refresh_token_record(&token_hash).await?;

        // Check if already used (REUSE DETECTION)
        if token_record.used {
            return self.handle_token_reuse(&token_record).await;
        }

        // Validate token is not revoked or expired
        self.validate_refresh_token(&token_record, session_id, machine_id)?;

        // Step 3: Mark token as used
        token_record.used = true;
        token_record.used_at = Some(current_timestamp());
        self.update_refresh_token_record(&token_record).await?;

        // Step 4: Get and validate session
        let session = self.get_session_internal(session_id).await?;
        self.check_session_validity(&session, session_id)?;

        // Step 5: Check identity frozen status
        let identity = self.identity_core.get_identity(session.identity_id).await?;

        if identity.status == zero_auth_identity_core::IdentityStatus::Frozen {
            return Err(SessionError::IdentityFrozen);
        }

        self.build_refreshed_tokens(&session, machine_id, &token_record)
            .await
    }

    /// Handle token reuse - revoke family and return error
    async fn handle_token_reuse(&self, token_record: &RefreshTokenRecord) -> Result<SessionTokens> {
        // SECURITY EVENT: Reuse detected!
        self.revoke_token_family_internal(token_record.token_family_id)
            .await?;

        // Publish security event
        self.event_publisher
            .publish_revocation_event(RevocationEvent {
                event_type: RevocationEventType::TokenFamilyRevoked,
                identity_id: Uuid::nil(),
                session_id: Some(token_record.session_id),
                machine_id: Some(token_record.machine_id),
                token_family_id: Some(token_record.token_family_id),
                timestamp: current_timestamp(),
                reason: Some("Refresh token reuse detected".to_string()),
            })
            .await?;

        Err(SessionError::RefreshTokenReuse {
            token_family_id: token_record.token_family_id,
            generation: token_record.generation,
        })
    }

    /// Validate a refresh token record
    fn validate_refresh_token(
        &self,
        token_record: &RefreshTokenRecord,
        session_id: Uuid,
        machine_id: Uuid,
    ) -> Result<()> {
        // Check if revoked
        if token_record.revoked {
            return Err(SessionError::SessionRevoked {
                reason: token_record
                    .revoked_reason
                    .clone()
                    .unwrap_or_else(|| "Token revoked".to_string()),
            });
        }

        // Check expiration
        if token_record.expires_at < current_timestamp() {
            return Err(SessionError::RefreshTokenExpired);
        }

        // Check session binding
        if token_record.session_id != session_id {
            return Err(SessionError::SessionBindingMismatch);
        }

        // Check machine binding
        if token_record.machine_id != machine_id {
            return Err(SessionError::MachineBindingMismatch);
        }

        Ok(())
    }

    fn check_session_validity(&self, session: &Session, session_id: Uuid) -> Result<()> {
        if session.revoked {
            return Err(SessionError::SessionRevoked {
                reason: session
                    .revoked_reason
                    .clone()
                    .unwrap_or_else(|| "Session revoked".to_string()),
            });
        }

        let now = current_timestamp();
        if session.expires_at < now {
            return Err(SessionError::SessionExpired {
                session_id,
                expired_at: session.expires_at,
            });
        }

        Ok(())
    }

    async fn build_refreshed_tokens(
        &self,
        session: &Session,
        machine_id: Uuid,
        token_record: &RefreshTokenRecord,
    ) -> Result<SessionTokens> {
        let machine = self.identity_core.get_machine_key(machine_id).await?;
        let capabilities = vec![format!("{:?}", machine.capabilities)];
        let scope = vec![
            format!("namespace:{}:*", machine.namespace_id),
            "session:refresh".to_string(),
        ];

        let new_access_token = self
            .issue_access_token(session, false, capabilities, scope)
            .await?;

        let new_refresh_token = self
            .generate_refresh_token(
                session.session_id,
                machine_id,
                token_record.token_family_id,
                token_record.generation + 1,
            )
            .await?;

        Ok(SessionTokens {
            access_token: new_access_token,
            refresh_token: new_refresh_token,
            session_id: session.session_id,
            expires_in: self.access_token_ttl,
            token_type: "Bearer".to_string(),
        })
    }

    /// Revoke a session
    pub(crate) async fn revoke_session_internal(&self, session_id: Uuid) -> Result<()> {
        // Get session
        let mut session = self.get_session_internal(session_id).await?;

        // Mark as revoked
        session.revoked = true;
        session.revoked_at = Some(current_timestamp());
        session.revoked_reason = Some("Session revoked by user".to_string());

        // Update in storage
        self.storage
            .put(CF_SESSIONS, session_id.as_bytes(), &session)
            .await?;

        // Publish revocation event
        self.event_publisher
            .publish_revocation_event(RevocationEvent {
                event_type: RevocationEventType::SessionRevoked,
                identity_id: session.identity_id,
                session_id: Some(session_id),
                machine_id: Some(session.machine_id),
                token_family_id: Some(session.token_family_id),
                timestamp: current_timestamp(),
                reason: Some("Session revoked".to_string()),
            })
            .await?;

        Ok(())
    }

    /// Revoke all sessions for an identity
    pub(crate) async fn revoke_all_sessions_internal(&self, identity_id: Uuid) -> Result<()> {
        use tracing::{info, warn};

        // Scan sessions_by_identity index
        let sessions_index: Vec<(Vec<u8>, Vec<u8>)> = self
            .storage
            .get_by_prefix(CF_SESSIONS_BY_IDENTITY, &identity_id)
            .await?;

        let mut revoked_count = 0;
        for (key_bytes, _) in sessions_index {
            if key_bytes.len() >= 32 {
                if let Ok(session_id_bytes) = key_bytes[16..32].try_into() {
                    let session_id = Uuid::from_bytes(session_id_bytes);

                    if let Err(e) = self.revoke_session_internal(session_id).await {
                        warn!("Failed to revoke session {}: {}", session_id, e);
                    } else {
                        revoked_count += 1;
                    }
                }
            }
        }

        info!(
            "Revoked {} sessions for identity {}",
            revoked_count, identity_id
        );

        // Publish aggregate event
        self.event_publisher
            .publish_revocation_event(RevocationEvent {
                event_type: RevocationEventType::AllSessionsRevoked,
                identity_id,
                session_id: None,
                machine_id: None,
                token_family_id: None,
                timestamp: current_timestamp(),
                reason: Some(format!("All sessions revoked ({} sessions)", revoked_count)),
            })
            .await?;

        Ok(())
    }

    /// Revoke all tokens in a token family
    pub(crate) async fn revoke_token_family_internal(&self, token_family_id: Uuid) -> Result<()> {
        use tracing::{info, warn};

        // Scan refresh_tokens_by_family index
        let tokens_index: Vec<(Vec<u8>, Vec<u8>)> = self
            .storage
            .get_by_prefix(CF_REFRESH_TOKENS_BY_FAMILY, &token_family_id)
            .await?;

        let mut revoked_count = 0;
        for (key_bytes, _) in tokens_index {
            if key_bytes.len() >= 48 {
                let token_hash_vec = key_bytes[16..48].to_vec();

                if let Ok(Some(mut token_record)) = self
                    .storage
                    .get::<Vec<u8>, RefreshTokenRecord>(CF_REFRESH_TOKENS, &token_hash_vec)
                    .await
                {
                    token_record.used = true;
                    token_record.used_at = Some(current_timestamp());

                    if let Err(e) = self
                        .storage
                        .put(CF_REFRESH_TOKENS, &token_hash_vec, &token_record)
                        .await
                    {
                        warn!("Failed to revoke token in family: {}", e);
                    } else {
                        revoked_count += 1;
                    }
                }
            }
        }

        info!(
            "Revoked {} tokens in family {}",
            revoked_count, token_family_id
        );

        // Publish event
        self.event_publisher
            .publish_revocation_event(RevocationEvent {
                event_type: RevocationEventType::TokenFamilyRevoked,
                identity_id: Uuid::nil(),
                session_id: None,
                machine_id: None,
                token_family_id: Some(token_family_id),
                timestamp: current_timestamp(),
                reason: Some(format!("Token family revoked ({} tokens)", revoked_count)),
            })
            .await?;

        Ok(())
    }

    /// Get a session by ID
    pub(crate) async fn get_session_internal(&self, session_id: Uuid) -> Result<Session> {
        let session: Session = self
            .storage
            .get(CF_SESSIONS, session_id.as_bytes())
            .await?
            .ok_or(SessionError::SessionNotFound(session_id))?;

        Ok(session)
    }
}
