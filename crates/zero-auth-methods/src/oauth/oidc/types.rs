//! OIDC-specific types for ID tokens, JWKS, and configuration.

use serde::{Deserialize, Serialize};

/// OIDC Configuration from discovery endpoint
/// From: https://accounts.google.com/.well-known/openid-configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfiguration {
    /// Issuer URL
    pub issuer: String,
    /// Authorization endpoint
    pub authorization_endpoint: String,
    /// Token endpoint
    pub token_endpoint: String,
    /// JWKS URI (JSON Web Key Set)
    pub jwks_uri: String,
    /// Supported response types
    pub response_types_supported: Vec<String>,
    /// Subject types supported
    pub subject_types_supported: Vec<String>,
    /// ID token signing algorithms supported
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Userinfo endpoint (optional, we prefer ID token claims)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
}

/// JSON Web Key Set from provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksKeySet {
    /// Array of JWK keys
    pub keys: Vec<JwksKey>,
}

impl JwksKeySet {
    /// Find key by Key ID (kid)
    pub fn find_key(&self, kid: &str) -> Option<&JwksKey> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }
}

/// Individual JSON Web Key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksKey {
    /// Key type (e.g., "RSA")
    pub kty: String,
    /// Key ID
    pub kid: Option<String>,
    /// Key use (e.g., "sig" for signature)
    #[serde(rename = "use")]
    pub use_: Option<String>,
    /// Algorithm (e.g., "RS256")
    pub alg: Option<String>,
    /// RSA modulus (base64url encoded)
    pub n: String,
    /// RSA public exponent (base64url encoded)
    pub e: String,
}

/// ID Token Claims (from JWT payload)
/// Standard OIDC claims: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer (provider URL)
    pub iss: String,
    /// Subject (provider's user ID)
    pub sub: String,
    /// Audience (our client ID)
    pub aud: String,
    /// Expiration time (Unix timestamp)
    pub exp: u64,
    /// Issued at time (Unix timestamp)
    pub iat: u64,
    /// Nonce (for replay protection)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Email address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Email verified flag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Full name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Profile picture URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    /// Given name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// Family name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
}

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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_jwks_cache_entry_validity() {
        let jwks = JwksKeySet {
            keys: vec![JwksKey {
                kty: "RSA".to_string(),
                kid: Some("key1".to_string()),
                use_: Some("sig".to_string()),
                alg: Some("RS256".to_string()),
                n: "test_n".to_string(),
                e: "AQAB".to_string(),
            }],
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

    #[test]
    fn test_jwks_cache_entry_clone() {
        let jwks = JwksKeySet {
            keys: vec![JwksKey {
                kty: "RSA".to_string(),
                kid: Some("key1".to_string()),
                use_: Some("sig".to_string()),
                alg: Some("RS256".to_string()),
                n: "test_n".to_string(),
                e: "AQAB".to_string(),
            }],
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
