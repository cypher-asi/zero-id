//! OAuth provider implementations.

pub mod epic;
pub mod google;
pub mod x;

pub use epic::EpicGamesProvider;
pub use google::GoogleProvider;
pub use x::XProvider;

use crate::oauth::config::OAuthConfig;

/// Trait for OAuth provider configuration
pub trait Provider {
    /// Provider name
    fn name(&self) -> &str;

    /// Authorization URL
    fn auth_url(&self) -> &str;

    /// Token exchange URL
    fn token_url(&self) -> &str;

    /// User info URL
    fn user_info_url(&self) -> &str;

    /// Default scopes
    fn scopes(&self) -> &[&str];

    /// Whether this provider supports OIDC
    fn supports_oidc(&self) -> bool;

    /// OIDC discovery URL (if supported)
    fn discovery_url(&self) -> Option<&str>;

    /// Build OAuth config
    fn build_config(
        &self,
        client_id: String,
        client_secret: String,
        redirect_uri: String,
    ) -> OAuthConfig;
}
