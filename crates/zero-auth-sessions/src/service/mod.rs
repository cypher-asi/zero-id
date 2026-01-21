//! Session manager service implementation.

mod introspection;
mod keys;
mod lifecycle;
mod tokens;

use crate::{errors::*, traits::*, types::*, EventPublisher, NoOpEventPublisher};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use zero_auth_identity_core::IdentityCore;
use zero_auth_storage::{column_families::*, Storage};
use zeroize::Zeroizing;

pub use tokens::{base64_url_encode, generate_random_bytes, sha256};

/// Session manager service implementation
pub struct SessionService<S: Storage, I: IdentityCore, E: EventPublisher> {
    pub(super) storage: Arc<S>,
    pub(super) identity_core: Arc<I>,
    pub(super) event_publisher: Arc<E>,
    pub(super) issuer: String,
    pub(super) default_audience: Vec<String>,
    pub(super) access_token_ttl: u64,  // seconds
    pub(super) refresh_token_ttl: u64, // seconds
    pub(super) signing_keys: Arc<RwLock<HashMap<String, JwtSigningKey>>>,
    pub(super) current_key_id: Arc<RwLock<String>>,
    pub(super) service_master_key: Zeroizing<[u8; 32]>,
}

impl<S: Storage, I: IdentityCore, E: EventPublisher> Drop for SessionService<S, I, E> {
    fn drop(&mut self) {
        // Zeroizing will automatically zero the key on drop
    }
}

impl<S: Storage, I: IdentityCore> SessionService<S, I, NoOpEventPublisher> {
    /// Create a new session service with no event publisher
    pub fn new(
        storage: Arc<S>,
        identity_core: Arc<I>,
        service_master_key: [u8; 32],
        issuer: String,
        default_audience: Vec<String>,
    ) -> Self {
        Self::with_event_publisher(
            storage,
            identity_core,
            Arc::new(NoOpEventPublisher),
            service_master_key,
            issuer,
            default_audience,
            900,     // Default: 15 minutes for access token
            2592000, // Default: 30 days for refresh token
        )
    }
}

impl<S: Storage, I: IdentityCore, E: EventPublisher> SessionService<S, I, E> {
    /// Create a new session service with custom event publisher
    #[allow(clippy::too_many_arguments)]
    pub fn with_event_publisher(
        storage: Arc<S>,
        identity_core: Arc<I>,
        event_publisher: Arc<E>,
        service_master_key: [u8; 32],
        issuer: String,
        default_audience: Vec<String>,
        access_token_ttl: u64,
        refresh_token_ttl: u64,
    ) -> Self {
        Self {
            storage,
            identity_core,
            event_publisher,
            issuer,
            default_audience,
            access_token_ttl,
            refresh_token_ttl,
            signing_keys: Arc::new(RwLock::new(HashMap::new())),
            current_key_id: Arc::new(RwLock::new(String::new())),
            service_master_key: Zeroizing::new(service_master_key),
        }
    }

    /// Initialize the service with initial signing key
    pub async fn initialize(&self) -> Result<()> {
        // Check if we have any signing keys
        let existing_keys = self.load_signing_keys().await?;

        if existing_keys.is_empty() {
            // Generate initial signing key
            let key = self.generate_signing_key(0).await?;
            let kid = format!("key_epoch_{}", key.epoch);

            // Store in database
            self.store_signing_key(&key).await?;

            // Update in-memory cache
            let mut keys = self.signing_keys.write().await;
            keys.insert(kid.clone(), key);

            let mut current_key = self.current_key_id.write().await;
            *current_key = kid;
        } else {
            // Load existing keys
            let mut keys = self.signing_keys.write().await;
            let mut current_kid = String::new();

            for key in existing_keys {
                let kid = format!("key_epoch_{}", key.epoch);
                if key.status == KeyStatus::Active {
                    current_kid = kid.clone();
                }
                keys.insert(kid, key);
            }

            if !current_kid.is_empty() {
                let mut current_key = self.current_key_id.write().await;
                *current_key = current_kid;
            }
        }

        Ok(())
    }

    /// Get refresh token record
    pub(super) async fn get_refresh_token_record(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<RefreshTokenRecord> {
        let record: RefreshTokenRecord = self
            .storage
            .get(CF_REFRESH_TOKENS, token_hash)
            .await?
            .ok_or(SessionError::RefreshTokenNotFound)?;

        Ok(record)
    }

    /// Update refresh token record
    pub(super) async fn update_refresh_token_record(
        &self,
        record: &RefreshTokenRecord,
    ) -> Result<()> {
        self.storage
            .put(CF_REFRESH_TOKENS, &record.token_hash, record)
            .await?;

        Ok(())
    }

    /// Make a key for token family indexing
    pub(super) fn make_family_key(&self, token_family_id: Uuid, generation: u32) -> Vec<u8> {
        let mut key = Vec::with_capacity(20);
        key.extend_from_slice(token_family_id.as_bytes());
        key.extend_from_slice(&generation.to_be_bytes());
        key
    }
}

#[async_trait]
impl<S: Storage, I: IdentityCore, E: EventPublisher> SessionManager for SessionService<S, I, E> {
    async fn create_session(
        &self,
        identity_id: Uuid,
        machine_id: Uuid,
        namespace_id: Uuid,
        mfa_verified: bool,
        capabilities: Vec<String>,
        scope: Vec<String>,
    ) -> Result<SessionTokens> {
        self.create_session_internal(
            identity_id,
            machine_id,
            namespace_id,
            mfa_verified,
            capabilities,
            scope,
        )
        .await
    }

    async fn refresh_session(
        &self,
        refresh_token: String,
        session_id: Uuid,
        machine_id: Uuid,
    ) -> Result<SessionTokens> {
        self.refresh_session_internal(refresh_token, session_id, machine_id)
            .await
    }

    async fn revoke_session(&self, session_id: Uuid) -> Result<()> {
        self.revoke_session_internal(session_id).await
    }

    async fn revoke_all_sessions(&self, identity_id: Uuid) -> Result<()> {
        self.revoke_all_sessions_internal(identity_id).await
    }

    async fn revoke_token_family(&self, token_family_id: Uuid) -> Result<()> {
        self.revoke_token_family_internal(token_family_id).await
    }

    async fn get_session(&self, session_id: Uuid) -> Result<Session> {
        self.get_session_internal(session_id).await
    }

    async fn introspect_token(
        &self,
        token: String,
        audience: Option<String>,
    ) -> Result<TokenIntrospection> {
        self.introspect_token_internal(token, audience).await
    }

    async fn get_jwks(&self) -> Result<JwksResponse> {
        self.get_jwks_internal().await
    }

    async fn rotate_signing_key(&self) -> Result<String> {
        self.rotate_signing_key_internal().await
    }
}
