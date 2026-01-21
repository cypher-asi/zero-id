//! Google OAuth/OIDC provider implementation.

use crate::oauth::config::OAuthConfig;
use crate::oauth::providers::Provider;

/// Google OAuth/OIDC provider
pub struct GoogleProvider;

impl Provider for GoogleProvider {
    fn name(&self) -> &str {
        "Google"
    }

    fn auth_url(&self) -> &str {
        "https://accounts.google.com/o/oauth2/v2/auth"
    }

    fn token_url(&self) -> &str {
        "https://oauth2.googleapis.com/token"
    }

    fn user_info_url(&self) -> &str {
        "https://www.googleapis.com/oauth2/v2/userinfo"
    }

    fn scopes(&self) -> &[&str] {
        &["openid", "email", "profile"]
    }

    fn supports_oidc(&self) -> bool {
        true
    }

    fn discovery_url(&self) -> Option<&str> {
        Some("https://accounts.google.com/.well-known/openid-configuration")
    }

    fn build_config(
        &self,
        client_id: String,
        client_secret: String,
        redirect_uri: String,
    ) -> OAuthConfig {
        OAuthConfig::google(client_id, client_secret, redirect_uri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_google_provider() {
        let provider = GoogleProvider;

        assert_eq!(provider.name(), "Google");
        assert!(provider.supports_oidc());
        assert!(provider.discovery_url().is_some());
        assert!(provider.auth_url().contains("google"));
        assert_eq!(provider.scopes().len(), 3);
    }

    #[test]
    fn test_google_config() {
        let provider = GoogleProvider;
        let config = provider.build_config(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://localhost/callback".to_string(),
        );

        assert_eq!(config.client_id, "client_id");
        assert!(config.auth_url.contains("google"));
        assert!(config.scopes.contains(&"email".to_string()));
    }
}
