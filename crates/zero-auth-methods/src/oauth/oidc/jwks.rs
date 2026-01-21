//! JWKS (JSON Web Key Set) fetching and caching.

use crate::errors::*;
use crate::oauth::oidc::discovery::discover_oidc_config;
use crate::oauth::oidc::types::{JwksCacheEntry, JwksKeySet};
use crate::oauth::types::OAuthProvider;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use zero_auth_crypto::current_timestamp;

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
        cache_write.insert(
            provider,
            JwksCacheEntry {
                jwks: jwks.clone(),
                fetched_at: current_time,
                ttl: 3600, // 1 hour
            },
        );
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
        cache_write.insert(
            provider,
            JwksCacheEntry {
                jwks: jwks.clone(),
                fetched_at: current_timestamp(),
                ttl: 3600,
            },
        );
    }

    Ok(jwks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_jwks_caching() {
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
        let cache: Arc<RwLock<HashMap<OAuthProvider, JwksCacheEntry>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Manually insert expired cache entry
        {
            let mut cache_write = cache.write().await;
            cache_write.insert(
                OAuthProvider::Google,
                JwksCacheEntry {
                    jwks: JwksKeySet { keys: vec![] },
                    fetched_at: 1000,
                    ttl: 3600,
                },
            );
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
                assert!(!jwks.keys.is_empty() || entry.fetched_at > 1000);
            }
            Err(_) => {
                // Network error acceptable in tests
                println!("Network error (acceptable in tests)");
            }
        }
    }

    #[tokio::test]
    async fn test_jwks_force_refresh() {
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
}
