//! OpenID Connect (OIDC) support for OAuth providers.
//!
//! This module provides:
//! - OIDC provider discovery
//! - ID token validation with JWT verification
//! - JWKS fetching and caching
//! - Nonce generation for replay protection

pub mod discovery;
pub mod jwks;
pub mod nonce;
pub mod types;
pub mod validation;

// Re-export commonly used items
pub use discovery::discover_oidc_config;
pub use jwks::{fetch_jwks, fetch_jwks_cached, fetch_jwks_fresh};
pub use nonce::{build_auth_url_with_nonce, generate_oidc_nonce};
pub use types::{IdTokenClaims, JwksCacheEntry, JwksKey, JwksKeySet, OidcConfiguration};
pub use validation::{validate_id_token, validate_id_token_with_cache};
