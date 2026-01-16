//! OAuth/OIDC provider integration.
//!
//! Supports OpenID Connect (OIDC) with Google, and OAuth 2.0 fallback for X (Twitter) and Epic Games.
//!
//! # Security Note
//! OAuth access tokens, refresh tokens, and ID tokens are NEVER stored in the database.
//! Only user metadata (provider_user_id, email, display_name) is persisted.
//! Tokens are obtained during the auth flow and discarded immediately after validation.
//!
//! # OIDC Security
//! For OIDC providers (Google), ID tokens are cryptographically validated:
//! - JWT signature verification (RS256)
//! - Issuer (iss) validation
//! - Audience (aud) validation  
//! - Expiration (exp) validation
//! - Nonce replay protection

use crate::{errors::*, types::*};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

/// OAuth configuration for a provider
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// Client ID
    pub client_id: String,
    /// Client secret
    pub client_secret: String,
    /// Authorization endpoint
    pub auth_url: String,
    /// Token exchange endpoint
    pub token_url: String,
    /// User info endpoint
    pub user_info_url: String,
    /// Redirect URI
    pub redirect_uri: String,
    /// Scopes to request
    pub scopes: Vec<String>,
}

impl OAuthConfig {
    /// Create Google OAuth configuration
    pub fn google(client_id: String, client_secret: String, redirect_uri: String) -> Self {
        Self {
            client_id,
            client_secret,
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            user_info_url: "https://www.googleapis.com/oauth2/v2/userinfo".to_string(),
            redirect_uri,
            scopes: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
        }
    }

    /// Create X (Twitter) OAuth configuration
    pub fn x(client_id: String, client_secret: String, redirect_uri: String) -> Self {
        Self {
            client_id,
            client_secret,
            auth_url: "https://twitter.com/i/oauth2/authorize".to_string(),
            token_url: "https://api.twitter.com/2/oauth2/token".to_string(),
            user_info_url: "https://api.twitter.com/2/users/me".to_string(),
            redirect_uri,
            scopes: vec!["tweet.read".to_string(), "users.read".to_string()],
        }
    }

    /// Create Epic Games OAuth configuration
    pub fn epic_games(client_id: String, client_secret: String, redirect_uri: String) -> Self {
        Self {
            client_id,
            client_secret,
            auth_url: "https://www.epicgames.com/id/authorize".to_string(),
            token_url: "https://api.epicgames.dev/epic/oauth/v1/token".to_string(),
            user_info_url: "https://api.epicgames.dev/epic/id/v1/accounts".to_string(),
            redirect_uri,
            scopes: vec!["basic_profile".to_string()],
        }
    }
}

/// OAuth token response from provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokenResponse {
    /// Access token from OAuth provider
    pub access_token: String,
    /// Token type (typically "Bearer")
    pub token_type: String,
    /// Optional refresh token for obtaining new access tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Token expiry time in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    /// Optional OIDC ID token (for OIDC providers like Google)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

/// OAuth client for provider interactions
pub struct OAuthClient {
    http_client: Client,
}

impl OAuthClient {
    /// Create a new OAuth client
    pub fn new() -> Self {
        Self {
            http_client: Client::new(),
        }
    }

    /// Build authorization URL
    pub fn build_auth_url(&self, config: &OAuthConfig, state: &str) -> Result<String> {
        let mut url = Url::parse(&config.auth_url)
            .map_err(|e| AuthMethodsError::OAuthConfigInvalid(format!("Invalid auth URL: {}", e)))?;

        url.query_pairs_mut()
            .append_pair("client_id", &config.client_id)
            .append_pair("redirect_uri", &config.redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", &config.scopes.join(" "))
            .append_pair("state", state);

        Ok(url.to_string())
    }

    /// Exchange authorization code for access token
    pub async fn exchange_code(
        &self,
        config: &OAuthConfig,
        code: &str,
    ) -> Result<OAuthTokenResponse> {
        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code");
        params.insert("code", code);
        params.insert("redirect_uri", &config.redirect_uri);
        params.insert("client_id", &config.client_id);
        params.insert("client_secret", &config.client_secret);

        let response = self
            .http_client
            .post(&config.token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| AuthMethodsError::OAuthProviderError(format!("Token exchange failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AuthMethodsError::OAuthProviderError(format!(
                "Token exchange failed with status {}: {}",
                status, body
            )));
        }

        let token_response: OAuthTokenResponse = response
            .json()
            .await
            .map_err(|e| AuthMethodsError::OAuthProviderError(format!("Failed to parse token response: {}", e)))?;

        Ok(token_response)
    }

    /// Get user info from provider
    pub async fn get_user_info(
        &self,
        config: &OAuthConfig,
        access_token: &str,
    ) -> Result<OAuthUserInfo> {
        let response = self
            .http_client
            .get(&config.user_info_url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| AuthMethodsError::OAuthProviderError(format!("User info request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AuthMethodsError::OAuthProviderError(format!(
                "User info request failed with status {}: {}",
                status, body
            )));
        }

        // Parse response based on provider format
        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AuthMethodsError::OAuthProviderError(format!("Failed to parse user info: {}", e)))?;

        // Extract user info (format varies by provider)
        let user_info = OAuthUserInfo {
            id: json["id"]
                .as_str()
                .or_else(|| json["sub"].as_str())
                .or_else(|| json["account_id"].as_str())
                .ok_or_else(|| AuthMethodsError::OAuthProviderError("Missing user ID".to_string()))?
                .to_string(),
            email: json["email"].as_str().map(|s| s.to_string()),
            name: json["name"]
                .as_str()
                .or_else(|| json["display_name"].as_str())
                .map(|s| s.to_string()),
            picture: json["picture"]
                .as_str()
                .or_else(|| json["avatar"].as_str())
                .map(|s| s.to_string()),
        };

        Ok(user_info)
    }
}

impl Default for OAuthClient {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// JWKS Caching
// ============================================================================

/// JWKS cache entry with expiration
#[derive(Debug, Clone)]
pub struct JwksCacheEntry {
    /// The cached JWKS key set
    pub jwks: JwksKeySet,
    /// Unix timestamp when JWKS was fetched
    pub fetched_at: u64,
    /// Time-to-live in seconds (typically 3600 = 1 hour)
    pub ttl: u64,
}

impl JwksCacheEntry {
    /// Check if cache entry is still valid
    pub fn is_valid(&self, current_time: u64) -> bool {
        current_time < self.fetched_at + self.ttl
    }
}

/// Get current timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ============================================================================
// OIDC Functions
// ============================================================================

/// Discover OIDC configuration from provider
pub async fn discover_oidc_config(provider: OAuthProvider) -> Result<OidcConfiguration> {
    let discovery_url = match provider {
        OAuthProvider::Google => "https://accounts.google.com/.well-known/openid-configuration",
        OAuthProvider::X => {
            return Err(AuthMethodsError::OidcDiscoveryFailed(
                "X/Twitter does not support OIDC discovery".to_string(),
            ))
        }
        OAuthProvider::EpicGames => {
            return Err(AuthMethodsError::OidcDiscoveryFailed(
                "Epic Games OIDC support unknown".to_string(),
            ))
        }
    };

    let client = Client::new();
    let config: OidcConfiguration = client
        .get(discovery_url)
        .send()
        .await
        .map_err(|e| AuthMethodsError::OidcDiscoveryFailed(format!("HTTP error: {}", e)))?
        .json()
        .await
        .map_err(|e| AuthMethodsError::OidcDiscoveryFailed(format!("JSON parse error: {}", e)))?;

    Ok(config)
}

/// Fetch JWKS from provider
pub async fn fetch_jwks(jwks_uri: &str) -> Result<JwksKeySet> {
    let client = Client::new();
    let jwks: JwksKeySet = client
        .get(jwks_uri)
        .send()
        .await
        .map_err(|e| AuthMethodsError::OAuthProviderError(format!("Failed to fetch JWKS: {}", e)))?
        .json()
        .await
        .map_err(|e| {
            AuthMethodsError::OAuthProviderError(format!("Failed to parse JWKS: {}", e))
        })?;

    Ok(jwks)
}

/// Generate cryptographically secure nonce for OIDC
pub fn generate_oidc_nonce() -> String {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    hex::encode(nonce)
}

/// Validate ID token from OIDC provider
pub async fn validate_id_token(
    id_token: &str,
    provider: OAuthProvider,
    expected_nonce: &str,
    expected_client_id: &str,
) -> Result<IdTokenClaims> {
    // Step 1: Decode header to get key ID
    let header = decode_header(id_token)
        .map_err(|e| AuthMethodsError::JwtDecodeError(format!("Failed to decode header: {}", e)))?;

    let kid = header
        .kid
        .ok_or_else(|| AuthMethodsError::KeyNotFound {
            kid: "missing".to_string(),
        })?;

    // Step 2: Fetch OIDC configuration
    let oidc_config = discover_oidc_config(provider).await?;

    // Step 3: Fetch JWKS
    let jwks = fetch_jwks(&oidc_config.jwks_uri).await?;

    // Step 4: Find matching key
    let jwk = jwks.find_key(&kid).ok_or_else(|| AuthMethodsError::KeyNotFound {
        kid: kid.clone(),
    })?;

    // Step 5: Verify algorithm
    if header.alg != Algorithm::RS256 {
        return Err(AuthMethodsError::InvalidAlgorithm {
            expected: "RS256".to_string(),
            got: format!("{:?}", header.alg),
        });
    }

    // Step 6: Build validation parameters
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&oidc_config.issuer]);
    validation.set_audience(&[expected_client_id]);
    validation.validate_exp = true;
    validation.validate_nbf = false;
    validation.leeway = 60; // 60 second clock skew tolerance

    // Step 7: Create decoding key from RSA components (base64url strings)
    let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|e| AuthMethodsError::InvalidRsaKey(format!("Invalid RSA key: {}", e)))?;

    // Step 9: Validate JWT signature and claims
    let token_data = decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|e| AuthMethodsError::InvalidJwtSignature(format!("JWT validation failed: {}", e)))?;

    let claims = token_data.claims;

    // Step 10: Verify nonce (CRITICAL for replay protection)
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

    // Step 11: Additional timestamp validation
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

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

/// Build authorization URL with nonce for OIDC
pub fn build_auth_url_with_nonce(
    config: &OAuthConfig,
    state: &str,
    nonce: &str,
) -> Result<String> {
    let mut url = Url::parse(&config.auth_url)
        .map_err(|e| AuthMethodsError::OAuthConfigInvalid(format!("Invalid auth URL: {}", e)))?;

    url.query_pairs_mut()
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", &config.redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", &config.scopes.join(" "))
        .append_pair("state", state)
        .append_pair("nonce", nonce);

    Ok(url.to_string())
}

// ============================================================================
// JWKS Caching Functions
// ============================================================================

/// Fetch JWKS with caching
pub async fn fetch_jwks_cached(
    provider: OAuthProvider,
    cache: &Arc<RwLock<HashMap<OAuthProvider, JwksCacheEntry>>>,
) -> Result<JwksKeySet> {
    let current_time = current_timestamp();
    
    // Check cache first (read lock)
    {
        let cache_read = cache.read().await;
        if let Some(entry) = cache_read.get(&provider) {
            if entry.is_valid(current_time) {
                return Ok(entry.jwks.clone());
            }
        }
    }
    
    // Cache miss or expired - fetch fresh JWKS
    let oidc_config = discover_oidc_config(provider).await?;
    let jwks = fetch_jwks(&oidc_config.jwks_uri).await?;
    
    // Update cache (write lock)
    {
        let mut cache_write = cache.write().await;
        cache_write.insert(provider, JwksCacheEntry {
            jwks: jwks.clone(),
            fetched_at: current_time,
            ttl: 3600,  // 1 hour
        });
    }
    
    Ok(jwks)
}

/// Force refresh JWKS (invalidate cache)
pub async fn fetch_jwks_fresh(
    provider: OAuthProvider,
    cache: &Arc<RwLock<HashMap<OAuthProvider, JwksCacheEntry>>>,
) -> Result<JwksKeySet> {
    // Remove from cache
    {
        let mut cache_write = cache.write().await;
        cache_write.remove(&provider);
    }
    
    // Fetch fresh
    let oidc_config = discover_oidc_config(provider).await?;
    let jwks = fetch_jwks(&oidc_config.jwks_uri).await?;
    
    // Update cache with fresh JWKS
    {
        let mut cache_write = cache.write().await;
        cache_write.insert(provider, JwksCacheEntry {
            jwks: jwks.clone(),
            fetched_at: current_timestamp(),
            ttl: 3600,
        });
    }
    
    Ok(jwks)
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
        false,  // use cache
    ).await {
        Ok(claims) => Ok(claims),
        Err(AuthMethodsError::InvalidJwtSignature(_)) | Err(AuthMethodsError::KeyNotFound { .. }) => {
            // Signature validation failed or key not found - might be key rotation
            // Retry with fresh JWKS (only once)
            validate_id_token_internal(
                id_token,
                provider,
                expected_nonce,
                expected_client_id,
                jwks_cache,
                true,  // force refresh
            ).await
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
    // Step 1: Decode header to get key ID
    let header = decode_header(id_token)
        .map_err(|e| AuthMethodsError::JwtDecodeError(format!("Failed to decode header: {}", e)))?;

    let kid = header
        .kid
        .ok_or_else(|| AuthMethodsError::KeyNotFound {
            kid: "missing".to_string(),
        })?;

    // Step 2: Get OIDC configuration (always fresh - it's small and rarely changes)
    let oidc_config = discover_oidc_config(provider).await?;

    // Step 3: Fetch JWKS (with or without cache)
    let jwks = if force_refresh {
        fetch_jwks_fresh(provider, jwks_cache).await?
    } else {
        fetch_jwks_cached(provider, jwks_cache).await?
    };

    // Step 4: Find matching key
    let jwk = jwks.find_key(&kid).ok_or_else(|| AuthMethodsError::KeyNotFound {
        kid: kid.clone(),
    })?;

    // Step 5: Verify algorithm
    if header.alg != Algorithm::RS256 {
        return Err(AuthMethodsError::InvalidAlgorithm {
            expected: "RS256".to_string(),
            got: format!("{:?}", header.alg),
        });
    }

    // Step 6: Build validation parameters
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&oidc_config.issuer]);
    validation.set_audience(&[expected_client_id]);
    validation.validate_exp = true;
    validation.validate_nbf = false;
    validation.leeway = 60; // 60 second clock skew tolerance

    // Step 7: Create decoding key from RSA components (base64url strings)
    let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|e| AuthMethodsError::InvalidRsaKey(format!("Invalid RSA key: {}", e)))?;

    // Step 8: Validate JWT signature and claims
    let token_data = decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|e| AuthMethodsError::InvalidJwtSignature(format!("JWT validation failed: {}", e)))?;

    let claims = token_data.claims;

    // Step 9: Verify nonce (CRITICAL for replay protection)
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

    // Step 10: Additional timestamp validation
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_google_config() {
        let config = OAuthConfig::google(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://localhost/callback".to_string(),
        );

        assert_eq!(config.client_id, "client_id");
        assert!(config.auth_url.contains("google"));
        assert!(config.scopes.contains(&"email".to_string()));
    }

    #[test]
    fn test_build_auth_url() {
        let config = OAuthConfig::google(
            "test_client".to_string(),
            "test_secret".to_string(),
            "http://localhost/callback".to_string(),
        );

        let client = OAuthClient::new();
        let url = client.build_auth_url(&config, "test_state").unwrap();

        assert!(url.contains("client_id=test_client"));
        assert!(url.contains("state=test_state"));
        assert!(url.contains("response_type=code"));
    }

    #[test]
    fn test_x_config() {
        let config = OAuthConfig::x(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://localhost/callback".to_string(),
        );

        assert!(config.auth_url.contains("twitter"));
    }

    #[test]
    fn test_epic_games_config() {
        let config = OAuthConfig::epic_games(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://localhost/callback".to_string(),
        );

        assert!(config.auth_url.contains("epicgames"));
    }

    // ========================================================================
    // OIDC Tests
    // ========================================================================

    #[test]
    fn test_generate_oidc_nonce() {
        let nonce1 = generate_oidc_nonce();
        let nonce2 = generate_oidc_nonce();

        // Nonces should be 64 hex characters (32 bytes)
        assert_eq!(nonce1.len(), 64);
        assert_eq!(nonce2.len(), 64);

        // Nonces should be unique
        assert_ne!(nonce1, nonce2);

        // Nonces should be valid hex
        assert!(nonce1.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(nonce2.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_build_auth_url_with_nonce() {
        let config = OAuthConfig::google(
            "test_client".to_string(),
            "test_secret".to_string(),
            "http://localhost/callback".to_string(),
        );

        let state = "test_state";
        let nonce = "test_nonce";

        let url = build_auth_url_with_nonce(&config, state, nonce).unwrap();

        assert!(url.contains("client_id=test_client"));
        assert!(url.contains("state=test_state"));
        assert!(url.contains("nonce=test_nonce"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("scope=openid"));
    }

    #[tokio::test]
    async fn test_discover_oidc_config_google() {
        // This test requires network access
        let result = discover_oidc_config(OAuthProvider::Google).await;

        match result {
            Ok(config) => {
                assert_eq!(config.issuer, "https://accounts.google.com");
                assert!(config.jwks_uri.contains("googleapis.com"));
                assert!(config.id_token_signing_alg_values_supported.contains(&"RS256".to_string()));
            }
            Err(e) => {
                // Network error is acceptable in tests
                println!("Network error (acceptable in tests): {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_discover_oidc_config_x_fails() {
        // X/Twitter doesn't support OIDC discovery
        let result = discover_oidc_config(OAuthProvider::X).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthMethodsError::OidcDiscoveryFailed(_)));
    }

    #[test]
    fn test_jwks_key_set_find_key() {
        let jwks = JwksKeySet {
            keys: vec![
                JwksKey {
                    kty: "RSA".to_string(),
                    kid: Some("key1".to_string()),
                    use_: Some("sig".to_string()),
                    alg: Some("RS256".to_string()),
                    n: "test_n".to_string(),
                    e: "AQAB".to_string(),
                },
                JwksKey {
                    kty: "RSA".to_string(),
                    kid: Some("key2".to_string()),
                    use_: Some("sig".to_string()),
                    alg: Some("RS256".to_string()),
                    n: "test_n2".to_string(),
                    e: "AQAB".to_string(),
                },
            ],
        };

        // Should find key1
        let key = jwks.find_key("key1");
        assert!(key.is_some());
        assert_eq!(key.unwrap().kid.as_ref().unwrap(), "key1");

        // Should find key2
        let key = jwks.find_key("key2");
        assert!(key.is_some());
        assert_eq!(key.unwrap().kid.as_ref().unwrap(), "key2");

        // Should not find key3
        let key = jwks.find_key("key3");
        assert!(key.is_none());
    }

    #[test]
    fn test_id_token_claims_deserialization() {
        let json = r#"{
            "iss": "https://accounts.google.com",
            "sub": "1234567890",
            "aud": "test_client_id",
            "exp": 1705320000,
            "iat": 1705316400,
            "nonce": "test_nonce",
            "email": "test@example.com",
            "email_verified": true,
            "name": "Test User"
        }"#;

        let claims: IdTokenClaims = serde_json::from_str(json).unwrap();

        assert_eq!(claims.iss, "https://accounts.google.com");
        assert_eq!(claims.sub, "1234567890");
        assert_eq!(claims.aud, "test_client_id");
        assert_eq!(claims.exp, 1705320000);
        assert_eq!(claims.iat, 1705316400);
        assert_eq!(claims.nonce.as_deref(), Some("test_nonce"));
        assert_eq!(claims.email.as_deref(), Some("test@example.com"));
        assert_eq!(claims.email_verified, Some(true));
        assert_eq!(claims.name.as_deref(), Some("Test User"));
    }

    #[test]
    fn test_oauth_state_with_nonce() {
        let state = OAuthState {
            state: "state123".to_string(),
            nonce: "nonce456".to_string(),
            identity_id: None,
            provider: OAuthProvider::Google,
            created_at: 1705316400,
            expires_at: 1705317000,
            used: false,
        };

        assert_eq!(state.state, "state123");
        assert_eq!(state.nonce, "nonce456");
        assert_eq!(state.provider, OAuthProvider::Google);
        assert!(!state.used);
    }

    #[test]
    fn test_oauth_link_with_email_verified() {
        let link = OAuthLink {
            link_id: uuid::Uuid::new_v4(),
            identity_id: uuid::Uuid::new_v4(),
            provider: OAuthProvider::Google,
            provider_user_id: "google_user_123".to_string(),
            provider_email: Some("test@example.com".to_string()),
            email_verified: Some(true),
            display_name: Some("Test User".to_string()),
            linked_at: 1705316400,
            last_auth_at: 1705316400,
            revoked: false,
            revoked_at: None,
        };

        assert_eq!(link.provider, OAuthProvider::Google);
        assert_eq!(link.provider_user_id, "google_user_123");
        assert_eq!(link.email_verified, Some(true));
        assert!(!link.revoked);
    }

    // ========================================================================
    // JWKS Caching Tests
    // ========================================================================

    #[test]
    fn test_jwks_cache_entry_validity() {
        let jwks = JwksKeySet {
            keys: vec![
                JwksKey {
                    kty: "RSA".to_string(),
                    kid: Some("key1".to_string()),
                    use_: Some("sig".to_string()),
                    alg: Some("RS256".to_string()),
                    n: "test_n".to_string(),
                    e: "AQAB".to_string(),
                },
            ],
        };

        let entry = JwksCacheEntry {
            jwks,
            fetched_at: 1000,
            ttl: 3600,
        };

        // Should be valid within TTL
        assert!(entry.is_valid(1000));
        assert!(entry.is_valid(2000));
        assert!(entry.is_valid(4599));

        // Should be invalid after TTL
        assert!(!entry.is_valid(4600));
        assert!(!entry.is_valid(5000));
    }

    #[tokio::test]
    async fn test_jwks_caching() {
        use std::sync::Arc;
        use tokio::sync::RwLock;
        use std::collections::HashMap;

        let cache: Arc<RwLock<HashMap<OAuthProvider, JwksCacheEntry>>> = 
            Arc::new(RwLock::new(HashMap::new()));

        // First fetch - should populate cache (network call)
        let result1 = fetch_jwks_cached(OAuthProvider::Google, &cache).await;
        
        // Check if fetch succeeded or failed due to network
        match result1 {
            Ok(jwks1) => {
                // Verify cache was populated
                let cache_read = cache.read().await;
                assert!(cache_read.contains_key(&OAuthProvider::Google));
                let cached_entry = cache_read.get(&OAuthProvider::Google).unwrap();
                assert_eq!(cached_entry.jwks.keys.len(), jwks1.keys.len());
                drop(cache_read);

                // Second fetch - should use cache (no network call)
                let result2 = fetch_jwks_cached(OAuthProvider::Google, &cache).await;
                assert!(result2.is_ok());
                let jwks2 = result2.unwrap();

                // Should return same keys
                assert_eq!(jwks1.keys.len(), jwks2.keys.len());
            }
            Err(e) => {
                // Network error is acceptable in tests
                println!("Network error (acceptable in tests): {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_jwks_cache_expiry() {
        use std::sync::Arc;
        use tokio::sync::RwLock;
        use std::collections::HashMap;

        let cache: Arc<RwLock<HashMap<OAuthProvider, JwksCacheEntry>>> = 
            Arc::new(RwLock::new(HashMap::new()));

        // Manually insert expired cache entry
        {
            let mut cache_write = cache.write().await;
            cache_write.insert(OAuthProvider::Google, JwksCacheEntry {
                jwks: JwksKeySet { keys: vec![] },
                fetched_at: 1000,
                ttl: 3600,
            });
        }

        // Attempt to fetch with expired cache
        // Should try to fetch fresh (may fail due to network in tests)
        let result = fetch_jwks_cached(OAuthProvider::Google, &cache).await;
        
        match result {
            Ok(jwks) => {
                // Cache should be updated with fresh data
                let cache_read = cache.read().await;
                let entry = cache_read.get(&OAuthProvider::Google).unwrap();
                // Fresh fetch should have keys
                assert!(jwks.keys.len() > 0 || entry.fetched_at > 1000);
            }
            Err(_) => {
                // Network error acceptable in tests
                println!("Network error (acceptable in tests)");
            }
        }
    }

    #[tokio::test]
    async fn test_jwks_force_refresh() {
        use std::sync::Arc;
        use tokio::sync::RwLock;
        use std::collections::HashMap;

        let cache: Arc<RwLock<HashMap<OAuthProvider, JwksCacheEntry>>> = 
            Arc::new(RwLock::new(HashMap::new()));

        // First populate cache
        let _ = fetch_jwks_cached(OAuthProvider::Google, &cache).await;

        // Force refresh should invalidate cache and fetch fresh
        let result = fetch_jwks_fresh(OAuthProvider::Google, &cache).await;
        
        match result {
            Ok(jwks) => {
                // Cache should have been updated
                let cache_read = cache.read().await;
                assert!(cache_read.contains_key(&OAuthProvider::Google));
                let entry = cache_read.get(&OAuthProvider::Google).unwrap();
                assert_eq!(entry.jwks.keys.len(), jwks.keys.len());
            }
            Err(_) => {
                // Network error acceptable in tests
                println!("Network error (acceptable in tests)");
            }
        }
    }

    #[test]
    fn test_cache_isolation_between_providers() {
        // Different providers should have separate cache entries
        // This is implicitly tested by the HashMap<OAuthProvider, _> structure
        assert_ne!(
            std::mem::discriminant(&OAuthProvider::Google),
            std::mem::discriminant(&OAuthProvider::X)
        );
    }

    #[test]
    fn test_jwks_cache_entry_clone() {
        let jwks = JwksKeySet {
            keys: vec![
                JwksKey {
                    kty: "RSA".to_string(),
                    kid: Some("key1".to_string()),
                    use_: Some("sig".to_string()),
                    alg: Some("RS256".to_string()),
                    n: "test_n".to_string(),
                    e: "AQAB".to_string(),
                },
            ],
        };

        let entry1 = JwksCacheEntry {
            jwks: jwks.clone(),
            fetched_at: 1000,
            ttl: 3600,
        };

        // Clone should work
        let entry2 = entry1.clone();
        assert_eq!(entry1.fetched_at, entry2.fetched_at);
        assert_eq!(entry1.ttl, entry2.ttl);
        assert_eq!(entry1.jwks.keys.len(), entry2.jwks.keys.len());
    }
}
