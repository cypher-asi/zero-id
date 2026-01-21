//! Session lifecycle integration tests.

use super::helpers::*;
use crate::*;
use uuid::Uuid;
use zero_auth_identity_core::IdentityCore;
use zero_auth_storage::Storage;

#[tokio::test]
async fn test_create_session_and_issue_tokens() {
    let (storage, _temp_dir) = create_test_storage();
    let identity_core = create_test_identity_service(storage.clone());
    let session_service = create_test_session_service(storage.clone(), identity_core.clone()).await;

    let (identity_id, machine_id, namespace_id) =
        create_test_identity_with_machine(&identity_core).await;

    let result = session_service
        .create_session(
            identity_id,
            machine_id,
            namespace_id,
            false,
            vec!["AUTHENTICATE".to_string()],
            vec!["default".to_string()],
        )
        .await;

    assert!(result.is_ok());
    let tokens = result.unwrap();

    assert!(!tokens.access_token.is_empty());
    assert!(!tokens.refresh_token.is_empty());
    assert_eq!(tokens.token_type, "Bearer");
    assert_eq!(tokens.expires_in, 900);

    let session = session_service
        .get_session(tokens.session_id)
        .await
        .unwrap();
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

    let (identity_id, machine_id, namespace_id) =
        create_test_identity_with_machine(&identity_core).await;

    let tokens = session_service
        .create_session(
            identity_id,
            machine_id,
            namespace_id,
            false,
            vec!["AUTHENTICATE".to_string()],
            vec!["default".to_string()],
        )
        .await
        .unwrap();

    let original_refresh_token = tokens.refresh_token.clone();
    let session_id = tokens.session_id;

    let refreshed_tokens = session_service
        .refresh_session(original_refresh_token.clone(), session_id, machine_id)
        .await
        .unwrap();

    assert!(!refreshed_tokens.access_token.is_empty());
    assert!(!refreshed_tokens.refresh_token.is_empty());
    assert_ne!(refreshed_tokens.refresh_token, original_refresh_token);
    assert_eq!(refreshed_tokens.session_id, session_id);

    // Try to reuse old refresh token - should fail
    let reuse_result = session_service
        .refresh_session(original_refresh_token, session_id, machine_id)
        .await;

    assert!(reuse_result.is_err());
    assert!(matches!(
        reuse_result.unwrap_err(),
        SessionError::RefreshTokenReuse { .. }
    ));
}

#[tokio::test]
async fn test_refresh_token_reuse_detection() {
    let (storage, _temp_dir) = create_test_storage();
    let identity_core = create_test_identity_service(storage.clone());
    let session_service = create_test_session_service(storage.clone(), identity_core.clone()).await;

    let (identity_id, machine_id, namespace_id) =
        create_test_identity_with_machine(&identity_core).await;

    let tokens = session_service
        .create_session(
            identity_id,
            machine_id,
            namespace_id,
            false,
            vec!["AUTHENTICATE".to_string()],
            vec!["default".to_string()],
        )
        .await
        .unwrap();

    let _new_tokens = session_service
        .refresh_session(tokens.refresh_token.clone(), tokens.session_id, machine_id)
        .await
        .unwrap();

    let reuse_result = session_service
        .refresh_session(tokens.refresh_token, tokens.session_id, machine_id)
        .await;

    assert!(reuse_result.is_err());
    match reuse_result.unwrap_err() {
        SessionError::RefreshTokenReuse {
            token_family_id,
            generation,
        } => {
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

    let (identity_id, machine_id, namespace_id) =
        create_test_identity_with_machine(&identity_core).await;

    let tokens = session_service
        .create_session(
            identity_id,
            machine_id,
            namespace_id,
            false,
            vec!["AUTHENTICATE".to_string()],
            vec!["default".to_string()],
        )
        .await
        .unwrap();

    let revoke_result = session_service.revoke_session(tokens.session_id).await;
    assert!(revoke_result.is_ok());

    let refresh_result = session_service
        .refresh_session(tokens.refresh_token, tokens.session_id, machine_id)
        .await;

    assert!(refresh_result.is_err());
}

#[tokio::test]
async fn test_frozen_identity_blocks_session_creation() {
    let (storage, _temp_dir) = create_test_storage();
    let identity_core = create_test_identity_service(storage.clone());
    let session_service = create_test_session_service(storage.clone(), identity_core.clone()).await;

    let (identity_id, machine_id, namespace_id) =
        create_test_identity_with_machine(&identity_core).await;

    // Manually freeze the identity
    use zero_auth_identity_core::{FreezeReason, Identity, IdentityStatus};
    use zero_auth_storage::column_families::CF_IDENTITIES;

    let mut identity: Identity = storage
        .get(CF_IDENTITIES, &identity_id)
        .await
        .unwrap()
        .unwrap();
    identity.status = IdentityStatus::Frozen;
    identity.frozen_at = Some(current_timestamp());
    identity.frozen_reason = Some(FreezeReason::Administrative.to_string());
    storage
        .put(CF_IDENTITIES, &identity_id, &identity)
        .await
        .unwrap();

    let result = session_service
        .create_session(
            identity_id,
            machine_id,
            namespace_id,
            false,
            vec!["AUTHENTICATE".to_string()],
            vec!["default".to_string()],
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SessionError::IdentityFrozen));
}

#[tokio::test]
async fn test_token_introspection_valid_token() {
    let (storage, _temp_dir) = create_test_storage();
    let identity_core = create_test_identity_service(storage.clone());
    let session_service = create_test_session_service(storage.clone(), identity_core.clone()).await;

    let (identity_id, machine_id, namespace_id) =
        create_test_identity_with_machine(&identity_core).await;

    let tokens = session_service
        .create_session(
            identity_id,
            machine_id,
            namespace_id,
            true,
            vec!["AUTHENTICATE".to_string()],
            vec!["default".to_string()],
        )
        .await
        .unwrap();

    let introspection = session_service
        .introspect_token(tokens.access_token, Some("zero-vault.test".to_string()))
        .await
        .unwrap();

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

    let introspection = session_service
        .introspect_token("invalid.token.here".to_string(), None)
        .await
        .unwrap();

    assert!(!introspection.active);
    assert!(introspection.token_type.is_none());
}

#[tokio::test]
async fn test_jwks_endpoint() {
    let (storage, _temp_dir) = create_test_storage();
    let identity_core = create_test_identity_service(storage.clone());
    let session_service = create_test_session_service(storage.clone(), identity_core.clone()).await;

    let jwks = session_service.get_jwks().await.unwrap();

    assert!(!jwks.keys.is_empty());

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

    let initial_jwks = session_service.get_jwks().await.unwrap();
    let initial_key_count = initial_jwks.keys.len();

    let new_kid = session_service.rotate_signing_key().await.unwrap();
    assert!(!new_kid.is_empty());

    let rotated_jwks = session_service.get_jwks().await.unwrap();

    assert!(rotated_jwks.keys.len() >= initial_key_count);

    assert!(rotated_jwks
        .keys
        .iter()
        .any(|k| k.kid.as_ref() == Some(&new_kid)));
}

#[tokio::test]
async fn test_revoked_machine_blocks_session_creation() {
    let (storage, _temp_dir) = create_test_storage();
    let identity_core = create_test_identity_service(storage.clone());
    let session_service = create_test_session_service(storage.clone(), identity_core.clone()).await;

    let (identity_id, machine_id, namespace_id) =
        create_test_identity_with_machine(&identity_core).await;

    identity_core
        .revoke_machine_key(
            machine_id,
            identity_id,
            "Test revocation".to_string(),
            false,
            "127.0.0.1".to_string(),
            "test".to_string(),
        )
        .await
        .unwrap();

    let result = session_service
        .create_session(
            identity_id,
            machine_id,
            namespace_id,
            false,
            vec!["AUTHENTICATE".to_string()],
            vec!["default".to_string()],
        )
        .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), SessionError::MachineRevoked));
}
