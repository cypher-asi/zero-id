//! JWT encoding/decoding and crypto tests.

use crate::*;

#[tokio::test]
async fn test_jwt_signing_key_generation() {
    let service_master_key = [42u8; 32];
    let seed = zero_auth_crypto::derive_jwt_signing_seed(&service_master_key, 1).unwrap();

    assert_eq!(seed.len(), 32);

    // Keys from different epochs should be different
    let seed2 = zero_auth_crypto::derive_jwt_signing_seed(&service_master_key, 2).unwrap();
    assert_ne!(*seed, *seed2);
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
    assert!(!encoded.contains('=')); // URL-safe encoding has no padding
}

#[test]
fn test_signing_key_generation() {
    use ed25519_dalek::SigningKey;

    let seed = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    assert_eq!(signing_key.to_bytes().len(), 32);
    assert_eq!(verifying_key.to_bytes().len(), 32);

    // Verify determinism
    let signing_key2 = SigningKey::from_bytes(&seed);
    assert_eq!(signing_key.to_bytes(), signing_key2.to_bytes());
}

#[test]
fn test_jwt_encode_decode() {
    use ed25519_dalek::SigningKey;
    use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

    let seed = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    // Create PKCS#8 DER for encoding
    let pkcs8_prefix: &[u8] = &[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
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
    let decoding_key =
        DecodingKey::from_ed_components(&public_key_b64).expect("Failed to create decoding key");

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&["test"]);
    validation.set_audience(&["test"]);
    validation.validate_exp = true;

    let decoded =
        decode::<TokenClaims>(&token, &decoding_key, &validation).expect("Failed to decode JWT");

    assert_eq!(decoded.claims.iss, claims.iss);
    assert_eq!(decoded.claims.sub, claims.sub);
}
