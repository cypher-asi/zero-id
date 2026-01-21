//! OAuth provider configuration.

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
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
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
