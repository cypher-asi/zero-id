//! ID token validation with JWT signature verification.

use crate::errors::*;
use crate::oauth::oidc::discovery::discover_oidc_config;
use crate::oauth::oidc::jwks::{fetch_jwks_cached, fetch_jwks_fresh};
use crate::oauth::oidc::types::{IdTokenClaims, JwksCacheEntry, JwksKeySet, OidcConfiguration};
use crate::oauth::types::OAuthProvider;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use zero_auth_crypto::current_timestamp;

/// Validate ID token from OIDC provider (without caching)
pub async fn validate_id_token(
    id_token: &str,
    provider: OAuthProvider,
    expected_nonce: &str,
    expected_client_id: &str,
) -> Result<IdTokenClaims> {
    // Step 1: Fetch OIDC configuration
    let oidc_config = discover_oidc_config(provider).await?;

    // Step 2: Fetch JWKS
    let jwks = crate::oauth::oidc::jwks::fetch_jwks(&oidc_config.jwks_uri).await?;

    validate_id_token_core(
        id_token,
        provider,
        expected_nonce,
        expected_client_id,
        &jwks,
        &oidc_config,
    )
    .await
}

/// Validate ID token with automatic JWKS refresh on failure
pub async fn validate_id_token_with_cache(
    id_token: &str,
    provider: OAuthProvider,
    expected_nonce: &str,
    expected_client_id: &str,
    jwks_cache: &Arc<RwLock<HashMap<OAuthProvider, JwksCacheEntry>>>,
) -> Result<IdTokenClaims> {
    // First attempt with cached JWKS
    match validate_id_token_internal(
        id_token,
        provider,
        expected_nonce,
        expected_client_id,
        jwks_cache,
        false, // use cache
    )
    .await
    {
        Ok(claims) => Ok(claims),
        Err(AuthMethodsError::InvalidJwtSignature(_))
        | Err(AuthMethodsError::KeyNotFound { .. }) => {
            // Signature validation failed or key not found - might be key rotation
            // Retry with fresh JWKS (only once)
            validate_id_token_internal(
                id_token,
                provider,
                expected_nonce,
                expected_client_id,
                jwks_cache,
                true, // force refresh
            )
            .await
        }
        Err(e) => Err(e),
    }
}

/// Internal validation with cache control
async fn validate_id_token_internal(
    id_token: &str,
    provider: OAuthProvider,
    expected_nonce: &str,
    expected_client_id: &str,
    jwks_cache: &Arc<RwLock<HashMap<OAuthProvider, JwksCacheEntry>>>,
    force_refresh: bool,
) -> Result<IdTokenClaims> {
    // Step 1: Get OIDC configuration (always fresh - it's small and rarely changes)
    let oidc_config = discover_oidc_config(provider).await?;

    // Step 2: Fetch JWKS (with or without cache)
    let jwks = if force_refresh {
        fetch_jwks_fresh(provider, jwks_cache).await?
    } else {
        fetch_jwks_cached(provider, jwks_cache).await?
    };

    validate_id_token_core(
        id_token,
        provider,
        expected_nonce,
        expected_client_id,
        &jwks,
        &oidc_config,
    )
    .await
}

async fn validate_id_token_core(
    id_token: &str,
    _provider: OAuthProvider,
    expected_nonce: &str,
    expected_client_id: &str,
    jwks: &JwksKeySet,
    oidc_config: &OidcConfiguration,
) -> Result<IdTokenClaims> {
    let header = decode_header(id_token)
        .map_err(|e| AuthMethodsError::JwtDecodeError(format!("Failed to decode header: {}", e)))?;

    let kid = header.kid.ok_or_else(|| AuthMethodsError::KeyNotFound {
        kid: "missing".to_string(),
    })?;

    let jwk = jwks
        .find_key(&kid)
        .ok_or_else(|| AuthMethodsError::KeyNotFound { kid: kid.clone() })?;

    if header.alg != Algorithm::RS256 {
        return Err(AuthMethodsError::InvalidAlgorithm {
            expected: "RS256".to_string(),
            got: format!("{:?}", header.alg),
        });
    }

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&oidc_config.issuer]);
    validation.set_audience(&[expected_client_id]);
    validation.validate_exp = true;
    validation.validate_nbf = false;
    validation.leeway = 60;

    let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|e| AuthMethodsError::InvalidRsaKey(format!("Invalid RSA key: {}", e)))?;

    let token_data =
        decode::<IdTokenClaims>(id_token, &decoding_key, &validation).map_err(|e| {
            AuthMethodsError::InvalidJwtSignature(format!("JWT validation failed: {}", e))
        })?;

    let claims = token_data.claims;
    let token_nonce = claims
        .nonce
        .as_ref()
        .ok_or(AuthMethodsError::MissingNonce)?;

    if token_nonce != expected_nonce {
        return Err(AuthMethodsError::NonceMismatch {
            expected: expected_nonce.to_string(),
            got: token_nonce.clone(),
        });
    }

    let current_time = current_timestamp();

    if claims.exp < current_time {
        return Err(AuthMethodsError::TokenExpired {
            expired_at: claims.exp,
            current_time,
        });
    }

    if claims.iat > current_time + 60 {
        return Err(AuthMethodsError::TokenIssuedInFuture {
            issued_at: claims.iat,
            current_time,
        });
    }

    Ok(claims)
}
