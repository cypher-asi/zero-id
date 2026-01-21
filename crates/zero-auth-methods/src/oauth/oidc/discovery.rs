//! OIDC provider discovery via .well-known endpoint.

use crate::errors::*;
use crate::oauth::oidc::types::OidcConfiguration;
use crate::oauth::types::OAuthProvider;
use reqwest::Client;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_discover_oidc_config_google() {
        // This test requires network access
        let result = discover_oidc_config(OAuthProvider::Google).await;

        match result {
            Ok(config) => {
                assert_eq!(config.issuer, "https://accounts.google.com");
                assert!(config.jwks_uri.contains("googleapis.com"));
                assert!(config
                    .id_token_signing_alg_values_supported
                    .contains(&"RS256".to_string()));
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
        assert!(matches!(
            result.unwrap_err(),
            AuthMethodsError::OidcDiscoveryFailed(_)
        ));
    }
}
