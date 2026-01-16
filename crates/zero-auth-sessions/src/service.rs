use crate::{
    errors::*, traits::*, types::*, EventPublisher, NoOpEventPublisher,
};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use zero_auth_crypto::derive_jwt_signing_seed;
use zero_auth_identity_core::IdentityCore;
use zero_auth_storage::{column_families::*, Storage};

/// Session manager service implementation
pub struct SessionService<S: Storage, I: IdentityCore, E: EventPublisher> {
    storage: Arc<S>,
    identity_core: Arc<I>,
    event_publisher: Arc<E>,
    issuer: String,
    default_audience: Vec<String>,
    access_token_ttl: u64,     // seconds
    refresh_token_ttl: u64,    // seconds
    signing_keys: Arc<RwLock<HashMap<String, JwtSigningKey>>>,
    current_key_id: Arc<RwLock<String>>,
    service_master_key: [u8; 32],
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
        )
    }
}

impl<S: Storage, I: IdentityCore, E: EventPublisher> SessionService<S, I, E> {
    /// Create a new session service with custom event publisher
    pub fn with_event_publisher(
        storage: Arc<S>,
        identity_core: Arc<I>,
        event_publisher: Arc<E>,
        service_master_key: [u8; 32],
        issuer: String,
        default_audience: Vec<String>,
    ) -> Self {
        Self {
            storage,
            identity_core,
            event_publisher,
            issuer,
            default_audience,
            access_token_ttl: 900,      // 15 minutes
            refresh_token_ttl: 2592000, // 30 days
            signing_keys: Arc::new(RwLock::new(HashMap::new())),
            current_key_id: Arc::new(RwLock::new(String::new())),
            service_master_key,
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

    /// Generate a new JWT signing key from service master key
    async fn generate_signing_key(&self, epoch: u64) -> Result<JwtSigningKey> {
        let seed = derive_jwt_signing_seed(&self.service_master_key, epoch)?;

        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let key_id = generate_random_bytes::<16>();

        Ok(JwtSigningKey {
            key_id,
            epoch,
            private_key: *seed,
            public_key: verifying_key.to_bytes(),
            created_at: current_timestamp(),
            expires_at: None,
            status: KeyStatus::Active,
        })
    }

    /// Store signing key in database
    async fn store_signing_key(&self, key: &JwtSigningKey) -> Result<()> {
        self.storage
            .put(CF_SIGNING_KEYS, &key.key_id, key)
            .await?;

        Ok(())
    }

    /// Load all signing keys from database
    async fn load_signing_keys(&self) -> Result<Vec<JwtSigningKey>> {
        // In a real implementation, we would scan the column family
        // For now, return empty vector if no keys exist
        Ok(Vec::new())
    }

    /// Issue a JWT access token
    async fn issue_access_token(
        &self,
        session: &Session,
        mfa_verified: bool,
        capabilities: Vec<String>,
        scope: Vec<String>,
    ) -> Result<String> {
        let now = current_timestamp();
        let exp = now + self.access_token_ttl;

        // Get current signing key
        let current_kid = self.current_key_id.read().await.clone();
        let keys = self.signing_keys.read().await;
        let signing_key = keys
            .get(&current_kid)
            .ok_or_else(|| SessionError::Other("No active signing key".to_string()))?;

        // Get machine to determine revocation epoch
        let machine = self
            .identity_core
            .get_machine_key(session.machine_id)
            .await?;

        let claims = TokenClaims {
            iss: self.issuer.clone(),
            sub: session.identity_id.to_string(),
            aud: self.default_audience.clone(),
            iat: now,
            exp,
            nbf: now,
            jti: Uuid::new_v4().to_string(),
            machine_id: session.machine_id.to_string(),
            namespace_id: session.namespace_id.to_string(),
            session_id: session.session_id.to_string(),
            mfa_verified,
            capabilities,
            scope,
            revocation_epoch: machine.epoch,
        };

        // Create JWT header with kid
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(current_kid);

        // Sign the JWT
        // For EdDSA with Ed25519, we need to convert the raw 32-byte seed to PKCS#8 DER format
        // PKCS#8 DER format for Ed25519: prefix + 32-byte seed
        let pkcs8_prefix: &[u8] = &[
            0x30, 0x2e, // SEQUENCE, length 46
            0x02, 0x01, 0x00, // INTEGER version 0
            0x30, 0x05, // SEQUENCE, length 5
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
            0x04, 0x22, // OCTET STRING, length 34
            0x04, 0x20, // OCTET STRING, length 32 (the actual key)
        ];
        
        let mut pkcs8_der = Vec::with_capacity(48);
        pkcs8_der.extend_from_slice(pkcs8_prefix);
        pkcs8_der.extend_from_slice(&signing_key.private_key);
        
        let encoding_key = EncodingKey::from_ed_der(&pkcs8_der);

        let token = encode(&header, &claims, &encoding_key)?;

        Ok(token)
    }

    /// Generate a refresh token
    async fn generate_refresh_token(
        &self,
        session_id: Uuid,
        machine_id: Uuid,
        token_family_id: Uuid,
        generation: u32,
    ) -> Result<String> {
        // Generate 32 random bytes
        let token_bytes = generate_random_bytes::<32>();
        let refresh_token = base64_url_encode(&token_bytes);

        // Hash the token for storage
        let token_hash = sha256(refresh_token.as_bytes());

        // Create token record
        let record = RefreshTokenRecord {
            token_hash,
            session_id,
            machine_id,
            token_family_id,
            generation,
            created_at: current_timestamp(),
            expires_at: current_timestamp() + self.refresh_token_ttl,
            used: false,
            used_at: None,
            revoked: false,
            revoked_at: None,
            revoked_reason: None,
        };

        // Store in database
        self.storage
            .put(CF_REFRESH_TOKENS, &token_hash, &record)
            .await?;

        // Also index by token family
        let family_key = self.make_family_key(token_family_id, generation);
        self.storage
            .put(CF_REFRESH_TOKENS_BY_FAMILY, &family_key, &token_hash)
            .await?;

        Ok(refresh_token)
    }

    /// Make a key for token family indexing
    fn make_family_key(&self, token_family_id: Uuid, generation: u32) -> Vec<u8> {
        let mut key = Vec::with_capacity(20);
        key.extend_from_slice(token_family_id.as_bytes());
        key.extend_from_slice(&generation.to_be_bytes());
        key
    }

    /// Get refresh token record
    async fn get_refresh_token_record(&self, token_hash: &[u8; 32]) -> Result<RefreshTokenRecord> {
        let record: RefreshTokenRecord = self
            .storage
            .get(CF_REFRESH_TOKENS, token_hash)
            .await?
            .ok_or(SessionError::RefreshTokenNotFound)?;

        Ok(record)
    }

    /// Update refresh token record
    async fn update_refresh_token_record(&self, record: &RefreshTokenRecord) -> Result<()> {
        self.storage
            .put(CF_REFRESH_TOKENS, &record.token_hash, record)
            .await?;

        Ok(())
    }

    /// Verify JWT token
    async fn verify_jwt_internal(&self, token: &str) -> Result<TokenClaims> {
        // Step 1: Parse header WITHOUT verification
        let header = jsonwebtoken::decode_header(token)?;

        // Step 2: STRICT algorithm check
        if header.alg != Algorithm::EdDSA {
            return Err(SessionError::InvalidAlgorithm {
                found: format!("{:?}", header.alg),
            });
        }

        // Step 3: Get kid
        let kid = header.kid.ok_or(SessionError::MissingKeyId)?;

        // Step 4: Lookup signing key
        let keys = self.signing_keys.read().await;
        let signing_key = keys
            .get(&kid)
            .ok_or_else(|| SessionError::UnknownKeyId(kid.clone()))?;

        // Step 5: Check key status
        let can_verify = match signing_key.status {
            KeyStatus::Active => true,
            KeyStatus::Rotating => {
                // During rotation, old key is valid for 1 hour overlap
                let now = current_timestamp();
                let rotation_started = signing_key.expires_at.unwrap_or(now);
                now < rotation_started + 3600 // 1 hour overlap
            }
            KeyStatus::Retired => false,
        };

        if !can_verify {
            return Err(SessionError::KeyRetired {
                kid,
                retired_at: signing_key.expires_at,
            });
        }

        // Step 6: Configure strict validation
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&self.default_audience);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        // Step 7: Verify signature
        // For EdDSA verification, convert public key to base64url format
        let public_key_b64 = base64_url_encode(&signing_key.public_key);
        let decoding_key = DecodingKey::from_ed_components(&public_key_b64)
            .map_err(|e| SessionError::Other(format!("Failed to create decoding key: {}", e)))?;
        let token_data = decode::<TokenClaims>(token, &decoding_key, &validation)?;

        Ok(token_data.claims)
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

    async fn refresh_session(
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
            // SECURITY EVENT: Reuse detected!
            self.revoke_token_family(token_record.token_family_id)
                .await?;

            // Publish security event
            self.event_publisher
                .publish_revocation_event(RevocationEvent {
                    event_type: RevocationEventType::TokenFamilyRevoked,
                    identity_id: Uuid::nil(), // We'll get this from session
                    session_id: Some(token_record.session_id),
                    machine_id: Some(token_record.machine_id),
                    token_family_id: Some(token_record.token_family_id),
                    timestamp: current_timestamp(),
                    reason: Some("Refresh token reuse detected".to_string()),
                })
                .await?;

            return Err(SessionError::RefreshTokenReuse {
                token_family_id: token_record.token_family_id,
                generation: token_record.generation,
            });
        }

        // Check if revoked
        if token_record.revoked {
            return Err(SessionError::SessionRevoked {
                reason: token_record
                    .revoked_reason
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

        // Step 3: Mark token as used
        token_record.used = true;
        token_record.used_at = Some(current_timestamp());
        self.update_refresh_token_record(&token_record).await?;

        // Step 4: Get and validate session
        let session = self.get_session(session_id).await?;

        if session.revoked {
            return Err(SessionError::SessionRevoked {
                reason: session
                    .revoked_reason
                    .unwrap_or_else(|| "Session revoked".to_string()),
            });
        }

        // Step 5: Check identity frozen status
        let identity = self
            .identity_core
            .get_identity(session.identity_id)
            .await?;

        if identity.status == zero_auth_identity_core::IdentityStatus::Frozen {
            return Err(SessionError::IdentityFrozen);
        }

        // Step 6: Get machine to get capabilities and scope
        let machine = self.identity_core.get_machine_key(machine_id).await?;

        let capabilities = vec![format!("{:?}", machine.capabilities)];
        let scope = vec!["default".to_string()]; // TODO: Get from machine or session

        // Step 7: Generate new tokens
        let new_access_token = self
            .issue_access_token(&session, false, capabilities, scope)
            .await?;

        let new_refresh_token = self
            .generate_refresh_token(
                session_id,
                machine_id,
                token_record.token_family_id,
                token_record.generation + 1,
            )
            .await?;

        Ok(SessionTokens {
            access_token: new_access_token,
            refresh_token: new_refresh_token,
            session_id,
            expires_in: self.access_token_ttl,
            token_type: "Bearer".to_string(),
        })
    }

    async fn revoke_session(&self, session_id: Uuid) -> Result<()> {
        // Get session
        let mut session = self.get_session(session_id).await?;

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

    async fn revoke_all_sessions(&self, identity_id: Uuid) -> Result<()> {
        // In a real implementation, we would scan the sessions_by_identity index
        // For now, just publish the event
        self.event_publisher
            .publish_revocation_event(RevocationEvent {
                event_type: RevocationEventType::AllSessionsRevoked,
                identity_id,
                session_id: None,
                machine_id: None,
                token_family_id: None,
                timestamp: current_timestamp(),
                reason: Some("All sessions revoked".to_string()),
            })
            .await?;

        Ok(())
    }

    async fn revoke_token_family(&self, token_family_id: Uuid) -> Result<()> {
        // In a real implementation, we would scan and revoke all tokens in the family
        // For now, just publish the event
        self.event_publisher
            .publish_revocation_event(RevocationEvent {
                event_type: RevocationEventType::TokenFamilyRevoked,
                identity_id: Uuid::nil(),
                session_id: None,
                machine_id: None,
                token_family_id: Some(token_family_id),
                timestamp: current_timestamp(),
                reason: Some("Token family revoked due to reuse detection".to_string()),
            })
            .await?;

        Ok(())
    }

    async fn get_session(&self, session_id: Uuid) -> Result<Session> {
        let session: Session = self
            .storage
            .get(CF_SESSIONS, session_id.as_bytes())
            .await?
            .ok_or(SessionError::SessionNotFound(session_id))?;

        Ok(session)
    }

    async fn introspect_token(
        &self,
        token: String,
        audience: Option<String>,
    ) -> Result<TokenIntrospection> {
        // Verify JWT signature
        let claims = match self.verify_jwt_internal(&token).await {
            Ok(claims) => claims,
            Err(_) => {
                // Token invalid
                return Ok(TokenIntrospection {
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
                });
            }
        };

        // Check audience if provided
        if let Some(aud) = &audience {
            if !claims.aud.contains(aud) {
                return Ok(TokenIntrospection {
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
                });
            }
        }

        // Parse UUIDs from claims
        let identity_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| SessionError::InvalidToken)?;
        let session_id = Uuid::parse_str(&claims.session_id)
            .map_err(|_| SessionError::InvalidToken)?;
        let machine_id = Uuid::parse_str(&claims.machine_id)
            .map_err(|_| SessionError::InvalidToken)?;

        // Check identity status
        let identity = match self.identity_core.get_identity(identity_id).await {
            Ok(identity) => identity,
            Err(_) => {
                return Ok(TokenIntrospection {
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
                });
            }
        };

        if identity.status != zero_auth_identity_core::IdentityStatus::Active {
            return Ok(TokenIntrospection {
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
            });
        }

        // Check session validity
        let session = match self.get_session(session_id).await {
            Ok(session) => session,
            Err(_) => {
                return Ok(TokenIntrospection {
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
                });
            }
        };

        if session.revoked {
            return Ok(TokenIntrospection {
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
            });
        }

        // Check machine revocation
        let machine = match self.identity_core.get_machine_key(machine_id).await {
            Ok(machine) => machine,
            Err(_) => {
                return Ok(TokenIntrospection {
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
                });
            }
        };

        if machine.revoked {
            return Ok(TokenIntrospection {
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
            });
        }

        // Check revocation epoch
        if claims.revocation_epoch < machine.epoch {
            return Ok(TokenIntrospection {
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
            });
        }

        // Token is valid
        Ok(TokenIntrospection {
            active: true,
            scope: Some(claims.scope.join(" ")),
            client_id: Some(claims.machine_id.to_string()),
            username: None,
            token_type: Some("Bearer".to_string()),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            nbf: Some(claims.nbf),
            sub: Some(claims.sub.to_string()),
            aud: Some(claims.aud),
            iss: Some(claims.iss),
            jti: Some(claims.jti),
        })
    }

    async fn get_jwks(&self) -> Result<JwksResponse> {
        let keys = self.signing_keys.read().await;
        let mut jwks_keys = Vec::new();

        for (kid, signing_key) in keys.iter() {
            // Only include active and rotating keys
            if matches!(
                signing_key.status,
                KeyStatus::Active | KeyStatus::Rotating
            ) {
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

    async fn rotate_signing_key(&self) -> Result<String> {
        // Get current key
        let current_kid = self.current_key_id.read().await.clone();
        let keys = self.signing_keys.read().await;
        let current_key = keys
            .get(&current_kid)
            .ok_or_else(|| SessionError::Other("No active signing key".to_string()))?;

        let new_epoch = current_key.epoch + 1;
        drop(keys); // Release read lock

        // Generate new key
        let new_key = self.generate_signing_key(new_epoch).await?;
        let new_kid = format!("key_epoch_{}", new_key.epoch);

        // Store new key
        self.store_signing_key(&new_key).await?;

        // Update current key to rotating status
        let mut keys = self.signing_keys.write().await;
        if let Some(old_key) = keys.get_mut(&current_kid) {
            old_key.status = KeyStatus::Rotating;
            old_key.expires_at = Some(current_timestamp() + 3600); // 1 hour overlap
            self.store_signing_key(old_key).await?;
        }

        // Add new key
        keys.insert(new_kid.clone(), new_key);

        // Update current key ID
        let mut current_key_id = self.current_key_id.write().await;
        *current_key_id = new_kid.clone();

        Ok(new_kid)
    }
}
