//! OAuth/OIDC provider integration.
//!
//! This module provides:
//! - Generic OAuth 2.0 client
//! - OpenID Connect (OIDC) support
//! - Provider-specific implementations (Google, X, Epic Games)
//!
//! # Security Note
//! OAuth access tokens, refresh tokens, and ID tokens are NEVER stored in the database.
//! Only user metadata (provider_user_id, email, display_name) is persisted.
//! Tokens are obtained during the auth flow and discarded immediately after validation.
//!
//! # OIDC Security
//! For OIDC providers (Google), ID tokens are cryptographically validated:
//! - JWT signature verification (RS256)
//! - Issuer (iss) validation
//! - Audience (aud) validation  
//! - Expiration (exp) validation
//! - Nonce replay protection

pub mod client;
pub mod config;
pub mod oidc;
pub mod providers;
pub mod types;

// Re-export commonly used items
pub use client::OAuthClient;
pub use config::OAuthConfig;
pub use providers::{EpicGamesProvider, GoogleProvider, Provider, XProvider};
pub use types::{OAuthLink, OAuthProvider, OAuthState, OAuthTokenResponse, OAuthUserInfo};

// Re-export OIDC functionality for backward compatibility
pub use oidc::{
    build_auth_url_with_nonce, discover_oidc_config, fetch_jwks, fetch_jwks_cached,
    fetch_jwks_fresh, generate_oidc_nonce, validate_id_token, validate_id_token_with_cache,
    IdTokenClaims, JwksCacheEntry, JwksKey, JwksKeySet, OidcConfiguration,
};
