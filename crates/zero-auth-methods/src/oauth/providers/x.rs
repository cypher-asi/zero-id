//! X (Twitter) OAuth provider implementation.

use crate::oauth::config::OAuthConfig;
use crate::oauth::providers::Provider;

/// X (Twitter) OAuth provider
///
/// Note: X uses OAuth 2.0 but does not support OIDC.
/// User info is obtained via their REST API.
pub struct XProvider;

impl Provider for XProvider {
    fn name(&self) -> &str {
        "X (Twitter)"
    }

    fn auth_url(&self) -> &str {
        "https://twitter.com/i/oauth2/authorize"
    }

    fn token_url(&self) -> &str {
        "https://api.twitter.com/2/oauth2/token"
    }

    fn user_info_url(&self) -> &str {
        "https://api.twitter.com/2/users/me"
    }

    fn scopes(&self) -> &[&str] {
        &["tweet.read", "users.read"]
    }

    fn supports_oidc(&self) -> bool {
        false
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
        OAuthConfig::x(client_id, client_secret, redirect_uri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x_provider() {
        let provider = XProvider;

        assert_eq!(provider.name(), "X (Twitter)");
        assert!(!provider.supports_oidc());
        assert!(provider.discovery_url().is_none());
        assert!(provider.auth_url().contains("twitter"));
        assert_eq!(provider.scopes().len(), 2);
    }

    #[test]
    fn test_x_config() {
        let provider = XProvider;
        let config = provider.build_config(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://localhost/callback".to_string(),
        );

        assert_eq!(config.client_id, "client_id");
        assert!(config.auth_url.contains("twitter"));
    }
}
