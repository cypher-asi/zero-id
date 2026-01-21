//! Epic Games OAuth provider implementation.

use crate::oauth::config::OAuthConfig;
use crate::oauth::providers::Provider;

/// Epic Games OAuth provider
///
/// Note: Epic Games uses OAuth 2.0. OIDC support is unknown.
pub struct EpicGamesProvider;

impl Provider for EpicGamesProvider {
    fn name(&self) -> &str {
        "Epic Games"
    }

    fn auth_url(&self) -> &str {
        "https://www.epicgames.com/id/authorize"
    }

    fn token_url(&self) -> &str {
        "https://api.epicgames.dev/epic/oauth/v1/token"
    }

    fn user_info_url(&self) -> &str {
        "https://api.epicgames.dev/epic/id/v1/accounts"
    }

    fn scopes(&self) -> &[&str] {
        &["basic_profile"]
    }

    fn supports_oidc(&self) -> bool {
        false // Unknown, assuming no for now
    }

    fn discovery_url(&self) -> Option<&str> {
        None
    }

    fn build_config(
        &self,
        client_id: String,
        client_secret: String,
        redirect_uri: String,
    ) -> OAuthConfig {
        OAuthConfig::epic_games(client_id, client_secret, redirect_uri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epic_provider() {
        let provider = EpicGamesProvider;

        assert_eq!(provider.name(), "Epic Games");
        assert!(!provider.supports_oidc());
        assert!(provider.discovery_url().is_none());
        assert!(provider.auth_url().contains("epicgames"));
        assert_eq!(provider.scopes().len(), 1);
    }

    #[test]
    fn test_epic_config() {
        let provider = EpicGamesProvider;
        let config = provider.build_config(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://localhost/callback".to_string(),
        );

        assert_eq!(config.client_id, "client_id");
        assert!(config.auth_url.contains("epicgames"));
    }
}
