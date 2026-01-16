use crate::*;
use std::sync::Arc;
use tempfile::TempDir;
use zero_auth_storage::RocksDbStorage;
use zero_auth_identity_core::{IdentityCore, IdentityCoreService};
use zero_auth_policy::PolicyEngineImpl;
use uuid::Uuid;
use async_trait::async_trait;

// Mock event publisher for tests
struct MockIdentityCoreEventPublisher;

#[async_trait]
impl zero_auth_identity_core::EventPublisher for MockIdentityCoreEventPublisher {
    async fn publish(&self, _event: zero_auth_identity_core::RevocationEvent) -> zero_auth_identity_core::Result<()> {
        Ok(())
    }
}

type TestIdentityService = IdentityCoreService<PolicyEngineImpl, MockIdentityCoreEventPublisher, RocksDbStorage>;

// Helper to create test storage
fn create_test_storage() -> (Arc<RocksDbStorage>, TempDir) {
    let temp_dir = tempfile::tempdir().unwrap();
    let db = RocksDbStorage::open(temp_dir.path()).unwrap();
    (Arc::new(db), temp_dir)
}

// Helper to create test identity service
fn create_test_identity_service(storage: Arc<RocksDbStorage>) -> Arc<TestIdentityService> {
    let policy = Arc::new(PolicyEngineImpl::new());
    let event_publisher = Arc::new(MockIdentityCoreEventPublisher);
    Arc::new(IdentityCoreService::new(policy, event_publisher, storage))
}

// Helper to create test session service
async fn create_test_session_service(
    storage: Arc<RocksDbStorage>,
    identity_core: Arc<TestIdentityService>,
) -> SessionService<RocksDbStorage, TestIdentityService, NoOpEventPublisher> {
    let service_master_key = [42u8; 32];
    let issuer = "zero-auth.test".to_string();
    let default_audience = vec!["zero-vault.test".to_string()];
    
    let service = SessionService::new(
        storage,
        identity_core,
        service_master_key,
        issuer,
        default_audience,
    );
    
    service.initialize().await.unwrap();
    service
}

// Helper to create test identity with machine
async fn create_test_identity_with_machine(
    identity_core: &TestIdentityService,
) -> (Uuid, Uuid, Uuid) {
    use zero_auth_identity_core::{CreateIdentityRequest, MachineKey};
    use zero_auth_crypto::{canonicalize_identity_creation_message, sign_message, Ed25519KeyPair};
    
    let now = crate::current_timestamp();
    let identity_id = Uuid::new_v4();
    let machine_id = Uuid::new_v4();
    let namespace_id = Uuid::new_v4();
    
    // Create Ed25519 keypair for identity
    let identity_keypair = Ed25519KeyPair::from_seed(&[42u8; 32]).unwrap();
    let central_public_key = identity_keypair.public_key_bytes();
    
    let signing_public_key = [2u8; 32];
    let encryption_public_key = [3u8; 32];
    
    // Create machine key
    let machine_key = MachineKey {
        machine_id,
        identity_id,
        namespace_id,
        signing_public_key,
        encryption_public_key,
        capabilities: zero_auth_crypto::MachineKeyCapabilities::AUTHENTICATE,
        epoch: 1,
        created_at: now,
        expires_at: None,
        last_used_at: None,
        device_name: "test-device".to_string(),
        device_platform: "test-platform".to_string(),
        revoked: false,
        revoked_at: None,
    };
    
    // Create canonical message
    let message = canonicalize_identity_creation_message(
        &identity_id,
        &central_public_key,
        &machine_id,
        &signing_public_key,
        &encryption_public_key,
        now,
    );
    
    // Sign the message
    let signature = sign_message(&identity_keypair, &message);
    
    // Create identity request
    let request = CreateIdentityRequest {
        identity_id,
        central_public_key,
        machine_key,
        authorization_signature: signature.to_vec(),
        namespace_name: Some("test-namespace".to_string()),
        created_at: now,
    };
    
    identity_core.create_identity(request).await.unwrap();
    
    (identity_id, machine_id, namespace_id)
}

#[tokio::test]
async fn test_jwt_signing_key_generation() {
    // Test JWT signing key derivation
    let service_master_key = [42u8; 32];
    let seed = zero_auth_crypto::derive_jwt_signing_seed(&service_master_key, 1).unwrap();
    
    assert_eq!(seed.len(), 32);
    
    // Keys from different epochs should be different
    let seed2 = zero_auth_crypto::derive_jwt_signing_seed(&service_master_key, 2).unwrap();
    assert_ne!(*seed, *seed2);
}

#[test]
fn test_token_claims_serialization() {
    let now = crate::current_timestamp();
    let claims = TokenClaims {
        iss: "zero-auth.test".to_string(),
        sub: uuid::Uuid::new_v4().to_string(),
        aud: vec!["zero-vault.test".to_string()],
        iat: now,
        exp: now + 900,
        nbf: now,
        jti: uuid::Uuid::new_v4().to_string(),
        machine_id: uuid::Uuid::new_v4().to_string(),
        namespace_id: uuid::Uuid::new_v4().to_string(),
        session_id: uuid::Uuid::new_v4().to_string(),
        mfa_verified: false,
        capabilities: vec!["AUTHENTICATE".to_string()],
        scope: vec!["default".to_string()],
        revocation_epoch: 1,
    };

    let json = serde_json::to_string(&claims).unwrap();
    assert!(json.contains("zero-auth.test"));
    
    let deserialized: TokenClaims = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.iss, claims.iss);
}

#[test]
fn test_session_serialization() {
    let now = crate::current_timestamp();
    let session = Session {
        session_id: uuid::Uuid::new_v4(),
        identity_id: uuid::Uuid::new_v4(),
        machine_id: uuid::Uuid::new_v4(),
        namespace_id: uuid::Uuid::new_v4(),
        token_family_id: uuid::Uuid::new_v4(),
        created_at: now,
        expires_at: now + 2592000,
        last_activity_at: now,
        revoked: false,
        revoked_at: None,
        revoked_reason: None,
    };

    let bytes = bincode::serialize(&session).unwrap();
    let deserialized: Session = bincode::deserialize(&bytes).unwrap();
    
    assert_eq!(deserialized.session_id, session.session_id);
    assert_eq!(deserialized.revoked, false);
}

#[test]
fn test_refresh_token_record_serialization() {
    let now = crate::current_timestamp();
    let record = RefreshTokenRecord {
        token_hash: [0u8; 32],
        session_id: uuid::Uuid::new_v4(),
        machine_id: uuid::Uuid::new_v4(),
        token_family_id: uuid::Uuid::new_v4(),
        generation: 1,
        created_at: now,
        expires_at: now + 2592000,
        used: false,
        used_at: None,
        revoked: false,
        revoked_at: None,
        revoked_reason: None,
    };

    let bytes = bincode::serialize(&record).unwrap();
    let deserialized: RefreshTokenRecord = bincode::deserialize(&bytes).unwrap();
    
    assert_eq!(deserialized.generation, 1);
    assert_eq!(deserialized.used, false);
}

#[test]
fn test_sha256_hashing() {
    let data = b"test data";
    let hash = sha256(data);
    
    assert_eq!(hash.len(), 32);
    
    // Same data should produce same hash
    let hash2 = sha256(data);
    assert_eq!(hash, hash2);
    
    // Different data should produce different hash
    let hash3 = sha256(b"different data");
    assert_ne!(hash, hash3);
}

#[test]
fn test_base64_encoding() {
    let data = [1u8, 2, 3, 4, 5];
    let encoded = base64_url_encode(&data);
    
    assert!(!encoded.is_empty());
    assert!(!encoded.contains('='));  // URL-safe encoding has no padding
}

#[test]
fn test_jwks_response_serialization() {
    let jwks = JwksResponse {
        keys: vec![JsonWebKey {
            kty: "OKP".to_string(),
            use_: Some("sig".to_string()),
            alg: Some("EdDSA".to_string()),
            kid: Some("key_epoch_1".to_string()),
            crv: "Ed25519".to_string(),
            x: "dGVzdCBwdWJsaWMga2V5".to_string(),
        }],
    };

    let json = serde_json::to_string(&jwks).unwrap();
    assert!(json.contains("EdDSA"));
    assert!(json.contains("Ed25519"));
}

#[test]
fn test_token_introspection_inactive() {
    let introspection = TokenIntrospection {
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
    };

    let json = serde_json::to_string(&introspection).unwrap();
    assert!(json.contains("\"active\":false"));
}

#[test]
fn test_revocation_event_serialization() {
    let now = crate::current_timestamp();
    let event = crate::RevocationEvent {
        event_type: crate::RevocationEventType::SessionRevoked,
        identity_id: uuid::Uuid::new_v4(),
        session_id: Some(uuid::Uuid::new_v4()),
        machine_id: None,
        token_family_id: None,
        timestamp: now,
        reason: Some("Test revocation".to_string()),
    };

    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("SessionRevoked"));
}

#[test]
fn test_signing_key_generation() {
    use ed25519_dalek::SigningKey;
    
    // Generate key
    let seed = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    
    // Verify key sizes
    assert_eq!(signing_key.to_bytes().len(), 32);
    assert_eq!(verifying_key.to_bytes().len(), 32);
    
    // Verify determinism
    let signing_key2 = SigningKey::from_bytes(&seed);
    assert_eq!(signing_key.to_bytes(), signing_key2.to_bytes());
}

#[test]
fn test_jwt_encode_decode() {
    use jsonwebtoken::{encode, decode, Header, Algorithm, EncodingKey, DecodingKey, Validation};
    use ed25519_dalek::SigningKey;
    
    // Create a key
    let seed = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    
    // Create PKCS#8 DER for encoding
    let pkcs8_prefix: &[u8] = &[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ];
    let mut pkcs8_der = Vec::with_capacity(48);
    pkcs8_der.extend_from_slice(pkcs8_prefix);
    pkcs8_der.extend_from_slice(&seed);
    
    let encoding_key = EncodingKey::from_ed_der(&pkcs8_der);
    
    // Create test claims
    let now = crate::current_timestamp();
    let claims = TokenClaims {
        iss: "test".to_string(),
        sub: uuid::Uuid::new_v4().to_string(),
        aud: vec!["test".to_string()],
        iat: now,
        exp: now + 900,
        nbf: now,
        jti: uuid::Uuid::new_v4().to_string(),
        machine_id: uuid::Uuid::new_v4().to_string(),
        namespace_id: uuid::Uuid::new_v4().to_string(),
        session_id: uuid::Uuid::new_v4().to_string(),
        mfa_verified: false,
        capabilities: vec![],
        scope: vec![],
        revocation_epoch: 1,
    };
    
    // Encode
    let header = Header::new(Algorithm::EdDSA);
    let token = encode(&header, &claims, &encoding_key).expect("Failed to encode JWT");
    
    // Decode
    let public_key_b64 = base64_url_encode(&verifying_key.to_bytes());
    let decoding_key = DecodingKey::from_ed_components(&public_key_b64).expect("Failed to create decoding key");
    
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&["test"]);
    validation.set_audience(&["test"]);
    validation.validate_exp = true;
    
    let decoded = decode::<TokenClaims>(&token, &decoding_key, &validation).expect("Failed to decode JWT");
    
    assert_eq!(decoded.claims.iss, claims.iss);
    assert_eq!(decoded.claims.sub, claims.sub);
}

// Integration Tests

#[tokio::test]
async fn test_create_session_and_issue_tokens() {
    let (storage, _temp_dir) = create_test_storage();
    let identity_core = create_test_identity_service(storage.clone());
    let session_service = create_test_session_service(storage.clone(), identity_core.clone()).await;
    
    // Create test identity and machine
    let (identity_id, machine_id, namespace_id) = create_test_identity_with_machine(&identity_core).await;
    
    // Create session
    let result = session_service.create_session(
        identity_id,
        machine_id,
        namespace_id,
        false,
        vec!["AUTHENTICATE".to_string()],
        vec!["default".to_string()],
    ).await;
    
    assert!(result.is_ok());
    let tokens = result.unwrap();
    
    // Verify token structure
    assert!(!tokens.access_token.is_empty());
    assert!(!tokens.refresh_token.is_empty());
    assert_eq!(tokens.token_type, "Bearer");
    assert_eq!(tokens.expires_in, 900); // 15 minutes
    
    // Verify session can be retrieved
    let session = session_service.get_session(tokens.session_id).await.unwrap();
    assert_eq!(session.identity_id, identity_id);
    assert_eq!(session.machine_id, machine_id);
    assert_eq!(session.namespace_id, namespace_id);
    assert!(!session.revoked);
}

#[tokio::test]
async fn test_refresh_token_rotation() {
    let (storage, _temp_dir) = create_test_storage();
    let identity_core = create_test_identity_service(storage.clone());
    let session_service = create_test_session_service(storage.clone(), identity_core.clone()).await;
    
    // Create test identity and machine
    let (identity_id, machine_id, namespace_id) = create_test_identity_with_machine(&identity_core).await;
    
    // Create initial session
    let tokens = session_service.create_session(
        identity_id,
        machine_id,
        namespace_id,
        false,
        vec!["AUTHENTICATE".to_string()],
        vec!["default".to_string()],
    ).await.unwrap();
    
    let original_refresh_token = tokens.refresh_token.clone();
    let session_id = tokens.session_id;
    
    // Refresh the session
    let refreshed_tokens = session_service.refresh_session(
        original_refresh_token.clone(),
        session_id,
        machine_id,
    ).await.unwrap();
    
    // Verify new tokens issued
    assert!(!refreshed_tokens.access_token.is_empty());
    assert!(!refreshed_tokens.refresh_token.is_empty());
    assert_ne!(refreshed_tokens.refresh_token, original_refresh_token);
    assert_eq!(refreshed_tokens.session_id, session_id);
    
    // Try to reuse old refresh token - should fail
    let reuse_result = session_service.refresh_session(
        original_refresh_token,
        session_id,
        machine_id,
    ).await;
    
    assert!(reuse_result.is_err());
    assert!(matches!(reuse_result.unwrap_err(), SessionError::RefreshTokenReuse { .. }));
}

#[tokio::test]
async fn test_refresh_token_reuse_detection() {
    let (storage, _temp_dir) = create_test_storage();
    let identity_core = create_test_identity_service(storage.clone());
    let session_service = create_test_session_service(storage.clone(), identity_core.clone()).await;
    
    // Create test identity and machine
    let (identity_id, machine_id, namespace_id) = create_test_identity_with_machine(&identity_core).await;
    
    // Create session
    let tokens = session_service.create_session(
        identity_id,
        machine_id,
        namespace_id,
        false,
        vec!["AUTHENTICATE".to_string()],
        vec!["default".to_string()],
    ).await.unwrap();
    
    // Use refresh token once
    let _new_tokens = session_service.refresh_session(
        tokens.refresh_token.clone(),
        tokens.session_id,
        machine_id,
    ).await.unwrap();
    
    // Try to use it again - should detect reuse
    let reuse_result = session_service.refresh_session(
        tokens.refresh_token,
        tokens.session_id,
        machine_id,
    ).await;
    
    assert!(reuse_result.is_err());
    match reuse_result.unwrap_err() {
        SessionError::RefreshTokenReuse { token_family_id, generation } => {
            assert_eq!(generation, 1);
            assert_ne!(token_family_id, Uuid::nil());
        }
        err => panic!("Expected RefreshTokenReuse error, got: {:?}", err),
    }
}

#[tokio::test]
async fn test_session_revocation() {
    let (storage, _temp_dir) = create_test_storage();
    let identity_core = create_test_identity_service(storage.clone());
    let session_service = create_test_session_service(storage.clone(), identity_core.clone()).await;
    
    // Create test identity and machine
    let (identity_id, machine_id, namespace_id) = create_test_identity_with_machine(&identity_core).await;
    
    // Create session
    let tokens = session_service.create_session(
        identity_id,
        machine_id,
        namespace_id,
        false,
        vec!["AUTHENTICATE".to_string()],
        vec!["default".to_string()],
    ).await.unwrap();
    
    // Revoke the session
    let revoke_result = session_service.revoke_session(tokens.session_id).await;
    assert!(revoke_result.is_ok());
    
    // Try to refresh with revoked session - should fail
    let refresh_result = session_service.refresh_session(
        tokens.refresh_token,
        tokens.session_id,
        machine_id,
    ).await;
    
    assert!(refresh_result.is_err());
}

#[tokio::test]
async fn test_frozen_identity_blocks_session_creation() {
    let (storage, _temp_dir) = create_test_storage();
    let identity_core = create_test_identity_service(storage.clone());
    let session_service = create_test_session_service(storage.clone(), identity_core.clone()).await;
    
    // Create test identity and machine
    let (identity_id, machine_id, namespace_id) = create_test_identity_with_machine(&identity_core).await;
    
    // Freeze the identity
    use zero_auth_identity_core::FreezeReason;
    identity_core.freeze_identity(
        identity_id,
        FreezeReason::Administrative,
    ).await.unwrap();
    
    // Try to create session with frozen identity - should fail
    let result = session_service.create_session(
        identity_id,
        machine_id,
        namespace_id,
        false,
        vec!["AUTHENTICATE".to_string()],
        vec!["default".to_string()],
    ).await;
    
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SessionError::IdentityFrozen));
}

#[tokio::test]
async fn test_token_introspection_valid_token() {
    let (storage, _temp_dir) = create_test_storage();
    let identity_core = create_test_identity_service(storage.clone());
    let session_service = create_test_session_service(storage.clone(), identity_core.clone()).await;
    
    // Create test identity and machine
    let (identity_id, machine_id, namespace_id) = create_test_identity_with_machine(&identity_core).await;
    
    // Create session
    let tokens = session_service.create_session(
        identity_id,
        machine_id,
        namespace_id,
        true, // MFA verified
        vec!["AUTHENTICATE".to_string()],
        vec!["default".to_string()],
    ).await.unwrap();
    
    // Introspect the token
    let introspection = session_service.introspect_token(
        tokens.access_token,
        Some("zero-vault.test".to_string()),
    ).await.unwrap();
    
    assert!(introspection.active);
    assert_eq!(introspection.token_type, Some("Bearer".to_string()));
    assert_eq!(introspection.iss, Some("zero-auth.test".to_string()));
    assert!(introspection.exp.is_some());
}

#[tokio::test]
async fn test_token_introspection_invalid_token() {
    let (storage, _temp_dir) = create_test_storage();
    let identity_core = create_test_identity_service(storage.clone());
    let session_service = create_test_session_service(storage.clone(), identity_core.clone()).await;
    
    // Introspect invalid token
    let introspection = session_service.introspect_token(
        "invalid.token.here".to_string(),
        None,
    ).await.unwrap();
    
    assert!(!introspection.active);
    assert!(introspection.token_type.is_none());
}

#[tokio::test]
async fn test_jwks_endpoint() {
    let (storage, _temp_dir) = create_test_storage();
    let identity_core = create_test_identity_service(storage.clone());
    let session_service = create_test_session_service(storage.clone(), identity_core.clone()).await;
    
    // Get JWKS
    let jwks = session_service.get_jwks().await.unwrap();
    
    // Should have at least one key
    assert!(!jwks.keys.is_empty());
    
    // Verify key structure
    let key = &jwks.keys[0];
    assert_eq!(key.kty, "OKP");
    assert_eq!(key.crv, "Ed25519");
    assert_eq!(key.alg, Some("EdDSA".to_string()));
    assert!(key.kid.is_some());
    assert!(!key.x.is_empty());
}

#[tokio::test]
async fn test_signing_key_rotation() {
    let (storage, _temp_dir) = create_test_storage();
    let identity_core = create_test_identity_service(storage.clone());
    let session_service = create_test_session_service(storage.clone(), identity_core.clone()).await;
    
    // Get initial JWKS
    let initial_jwks = session_service.get_jwks().await.unwrap();
    let initial_key_count = initial_jwks.keys.len();
    
    // Rotate signing key
    let new_kid = session_service.rotate_signing_key().await.unwrap();
    assert!(!new_kid.is_empty());
    
    // Get JWKS after rotation
    let rotated_jwks = session_service.get_jwks().await.unwrap();
    
    // Should have more keys (old + new during overlap)
    assert!(rotated_jwks.keys.len() >= initial_key_count);
    
    // New key should be present
    assert!(rotated_jwks.keys.iter().any(|k| k.kid.as_ref() == Some(&new_kid)));
}

#[tokio::test]
async fn test_revoked_machine_blocks_session_creation() {
    let (storage, _temp_dir) = create_test_storage();
    let identity_core = create_test_identity_service(storage.clone());
    let session_service = create_test_session_service(storage.clone(), identity_core.clone()).await;
    
    // Create test identity and machine
    let (identity_id, machine_id, namespace_id) = create_test_identity_with_machine(&identity_core).await;
    
    // Revoke the machine
    identity_core.revoke_machine_key(machine_id, identity_id, "Test revocation".to_string()).await.unwrap();
    
    // Try to create session with revoked machine - should fail
    let result = session_service.create_session(
        identity_id,
        machine_id,
        namespace_id,
        false,
        vec!["AUTHENTICATE".to_string()],
        vec!["default".to_string()],
    ).await;
    
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SessionError::MachineRevoked));
}
