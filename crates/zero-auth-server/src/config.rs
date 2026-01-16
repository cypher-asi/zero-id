use anyhow::Result;
use std::net::SocketAddr;
use std::path::PathBuf;

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
    
    /// Access token expiry (seconds) - loaded from config but expiry is currently handled by session service
    #[allow(dead_code)]
    pub access_token_expiry: u64,
    
    /// Refresh token expiry (seconds) - loaded from config but expiry is currently handled by session service
    #[allow(dead_code)]
    pub refresh_token_expiry: u64,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        let bind_address = std::env::var("BIND_ADDRESS")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
            .parse()?;

        let database_path = std::env::var("DATABASE_PATH")
            .unwrap_or_else(|_| "./data/zero-auth.db".to_string())
            .into();

        let service_master_key = {
            let hex_key = std::env::var("SERVICE_MASTER_KEY")
                .expect("SERVICE_MASTER_KEY environment variable required");
            let bytes = hex::decode(&hex_key)?;
            if bytes.len() != 32 {
                anyhow::bail!("SERVICE_MASTER_KEY must be 32 bytes (64 hex chars)");
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            key
        };

        let jwt_issuer = std::env::var("JWT_ISSUER")
            .unwrap_or_else(|_| "https://zero-auth.cypher.io".to_string());

        let jwt_audience = std::env::var("JWT_AUDIENCE")
            .unwrap_or_else(|_| "zero-vault".to_string());

        let access_token_expiry = std::env::var("ACCESS_TOKEN_EXPIRY_SECONDS")
            .unwrap_or_else(|_| "900".to_string()) // 15 minutes
            .parse()?;

        let refresh_token_expiry = std::env::var("REFRESH_TOKEN_EXPIRY_SECONDS")
            .unwrap_or_else(|_| "2592000".to_string()) // 30 days
            .parse()?;

        Ok(Config {
            bind_address,
            database_path,
            service_master_key,
            jwt_issuer,
            jwt_audience,
            access_token_expiry,
            refresh_token_expiry,
        })
    }
}
