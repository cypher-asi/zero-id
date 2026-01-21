//! Generic OAuth client for provider interactions.

use crate::errors::*;
use crate::oauth::config::OAuthConfig;
use crate::oauth::types::{OAuthTokenResponse, OAuthUserInfo};
use reqwest::Client;
use std::collections::HashMap;
use url::Url;

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
        let mut url = Url::parse(&config.auth_url).map_err(|e| {
            AuthMethodsError::OAuthConfigInvalid(format!("Invalid auth URL: {}", e))
        })?;

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
            .map_err(|e| {
                AuthMethodsError::OAuthProviderError(format!("Token exchange failed: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AuthMethodsError::OAuthProviderError(format!(
                "Token exchange failed with status {}: {}",
                status, body
            )));
        }

        let token_response: OAuthTokenResponse = response.json().await.map_err(|e| {
            AuthMethodsError::OAuthProviderError(format!("Failed to parse token response: {}", e))
        })?;

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
            .map_err(|e| {
                AuthMethodsError::OAuthProviderError(format!("User info request failed: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AuthMethodsError::OAuthProviderError(format!(
                "User info request failed with status {}: {}",
                status, body
            )));
        }

        // Parse response based on provider format
        let json: serde_json::Value = response.json().await.map_err(|e| {
            AuthMethodsError::OAuthProviderError(format!("Failed to parse user info: {}", e))
        })?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::config::OAuthConfig;

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
}
