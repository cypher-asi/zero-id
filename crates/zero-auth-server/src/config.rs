use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

/// OAuth provider configuration
#[derive(Clone)]
pub struct OAuthProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

// Custom Debug implementation to prevent secret leakage
impl std::fmt::Debug for OAuthProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthProviderConfig")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to bind the server to
    pub bind_address: SocketAddr,

    /// Path to RocksDB database
    pub database_path: PathBuf,

    /// Service master key (hex-encoded 32 bytes)
    pub service_master_key: [u8; 32],

    /// JWT issuer
    pub jwt_issuer: String,

    /// JWT audience
    pub jwt_audience: String,

    /// Access token expiry (seconds)
    pub access_token_expiry: u64,

    /// Refresh token expiry (seconds)
    pub refresh_token_expiry: u64,

    /// OAuth provider configurations
    pub oauth_google: Option<OAuthProviderConfig>,
    pub oauth_x: Option<OAuthProviderConfig>,
    pub oauth_epic: Option<OAuthProviderConfig>,

    /// CORS allowed origins (comma-separated list)
    pub cors_allowed_origins: Vec<String>,

    /// Trusted proxy IP addresses (for X-Forwarded-For validation)
    /// Only requests from these IPs will have their X-Forwarded-For header trusted
    pub trusted_proxies: Vec<IpAddr>,
}

/// Runtime mode selection for safety-sensitive defaults
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    Dev,
    Prod,
}

impl RunMode {
    fn from_env() -> Result<Self> {
        let raw = std::env::var("RUN_MODE").unwrap_or_else(|_| "prod".to_string());
        match raw.to_lowercase().as_str() {
            "dev" | "development" => Ok(Self::Dev),
            "prod" | "production" => Ok(Self::Prod),
            _ => anyhow::bail!("Invalid RUN_MODE: {} (expected dev or prod)", raw),
        }
    }
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        let run_mode = RunMode::from_env()?;

        let bind_address = Self::load_bind_address()?;
        let database_path = Self::load_database_path();
        let service_master_key = Self::load_service_master_key(run_mode)?;
        let jwt_issuer = Self::load_jwt_issuer();
        let jwt_audience = Self::load_jwt_audience();
        let access_token_expiry = Self::load_access_token_expiry()?;
        let refresh_token_expiry = Self::load_refresh_token_expiry()?;
        let (oauth_google, oauth_x, oauth_epic) = Self::load_oauth_configs();
        let cors_allowed_origins = Self::load_cors_allowed_origins();
        let trusted_proxies = Self::load_trusted_proxies();

        Ok(Config {
            bind_address,
            database_path,
            service_master_key,
            jwt_issuer,
            jwt_audience,
            access_token_expiry,
            refresh_token_expiry,
            oauth_google,
            oauth_x,
            oauth_epic,
            cors_allowed_origins,
            trusted_proxies,
        })
    }

    fn load_bind_address() -> Result<SocketAddr> {
        std::env::var("BIND_ADDRESS")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
            .parse()
            .map_err(Into::into)
    }

    fn load_database_path() -> PathBuf {
        std::env::var("DATABASE_PATH")
            .unwrap_or_else(|_| "./data/zero-auth.db".to_string())
            .into()
    }

    fn load_service_master_key(run_mode: RunMode) -> Result<[u8; 32]> {
        match std::env::var("SERVICE_MASTER_KEY") {
            Ok(hex_key) => {
                let bytes = hex::decode(&hex_key)?;
                if bytes.len() != 32 {
                    anyhow::bail!("SERVICE_MASTER_KEY must be 32 bytes (64 hex chars)");
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                Ok(key)
            }
            Err(_) => {
                if run_mode != RunMode::Dev {
                    anyhow::bail!("SERVICE_MASTER_KEY must be set when RUN_MODE is prod");
                }

                // Generate a random key in dev mode only
                use rand::RngCore;
                let mut key = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut key);

                eprintln!("⚠️  WARNING: SERVICE_MASTER_KEY not set - generated a dev-only key");
                eprintln!("⚠️  This key is only valid for this session!");
                eprintln!("⚠️  For production, set SERVICE_MASTER_KEY environment variable.");
                eprintln!();

                Ok(key)
            }
        }
    }

    fn load_jwt_issuer() -> String {
        std::env::var("JWT_ISSUER").unwrap_or_else(|_| "https://zero-auth.cypher.io".to_string())
    }

    fn load_jwt_audience() -> String {
        std::env::var("JWT_AUDIENCE").unwrap_or_else(|_| "zero-vault".to_string())
    }

    fn load_access_token_expiry() -> Result<u64> {
        std::env::var("ACCESS_TOKEN_EXPIRY_SECONDS")
            .unwrap_or_else(|_| "900".to_string()) // 15 minutes
            .parse()
            .map_err(Into::into)
    }

    fn load_refresh_token_expiry() -> Result<u64> {
        std::env::var("REFRESH_TOKEN_EXPIRY_SECONDS")
            .unwrap_or_else(|_| "2592000".to_string()) // 30 days
            .parse()
            .map_err(Into::into)
    }

    fn load_oauth_configs() -> (
        Option<OAuthProviderConfig>,
        Option<OAuthProviderConfig>,
        Option<OAuthProviderConfig>,
    ) {
        (
            Self::load_oauth_config(
                "OAUTH_GOOGLE_CLIENT_ID",
                "OAUTH_GOOGLE_CLIENT_SECRET",
                "OAUTH_GOOGLE_REDIRECT_URI",
            ),
            Self::load_oauth_config(
                "OAUTH_X_CLIENT_ID",
                "OAUTH_X_CLIENT_SECRET",
                "OAUTH_X_REDIRECT_URI",
            ),
            Self::load_oauth_config(
                "OAUTH_EPIC_CLIENT_ID",
                "OAUTH_EPIC_CLIENT_SECRET",
                "OAUTH_EPIC_REDIRECT_URI",
            ),
        )
    }

    fn load_oauth_config(
        client_id_key: &str,
        client_secret_key: &str,
        redirect_uri_key: &str,
    ) -> Option<OAuthProviderConfig> {
        let client_id = std::env::var(client_id_key).ok()?;
        let client_secret = std::env::var(client_secret_key).ok()?;
        let redirect_uri = std::env::var(redirect_uri_key).ok()?;
        Some(OAuthProviderConfig {
            client_id,
            client_secret,
            redirect_uri,
        })
    }

    fn load_cors_allowed_origins() -> Vec<String> {
        std::env::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:3000".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    fn load_trusted_proxies() -> Vec<IpAddr> {
        // Format: comma-separated list of IP addresses
        // Example: "10.0.0.1,172.16.0.1,192.168.1.1"
        std::env::var("TRUSTED_PROXIES")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(|s| {
                s.parse::<IpAddr>().ok().or_else(|| {
                    eprintln!("Warning: Invalid IP address in TRUSTED_PROXIES: {}", s);
                    None
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_provider_config_debug_redacts_secret() {
        let config = OAuthProviderConfig {
            client_id: "test_client_id".to_string(),
            client_secret: "super_secret_key_67890".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
        };

        let debug_output = format!("{:?}", config);

        // Secret should be redacted
        assert!(!debug_output.contains("super_secret_key_67890"));
        assert!(debug_output.contains("[REDACTED]"));

        // Other fields should be visible
        assert!(debug_output.contains("test_client_id"));
        assert!(debug_output.contains("https://example.com/callback"));
    }
}
