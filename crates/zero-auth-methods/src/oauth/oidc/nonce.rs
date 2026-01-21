//! OIDC nonce generation and URL building with nonce support.

use crate::errors::*;
use crate::oauth::config::OAuthConfig;
use url::Url;

/// Generate cryptographically secure nonce for OIDC
pub fn generate_oidc_nonce() -> String {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    hex::encode(nonce)
}

/// Build authorization URL with nonce for OIDC
pub fn build_auth_url_with_nonce(config: &OAuthConfig, state: &str, nonce: &str) -> Result<String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::config::OAuthConfig;

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
}
