//! Type serialization tests.

use crate::*;

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
    assert!(!deserialized.revoked);
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
    assert!(!deserialized.used);
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
        identity_id: uuid::Uuid::nil(),
        machine_id: uuid::Uuid::nil(),
        namespace_id: uuid::Uuid::nil(),
        session_id: uuid::Uuid::nil(),
        mfa_verified: false,
        capabilities: Vec::new(),
        scopes: Vec::new(),
        revocation_epoch: 0,
        issued_at: 0,
        expires_at: 0,
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
