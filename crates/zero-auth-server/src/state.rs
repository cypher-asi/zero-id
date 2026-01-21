use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use zero_auth_identity_core::IdentityCoreService;
use zero_auth_integrations::IntegrationsService;
use zero_auth_methods::AuthMethodsService;
use zero_auth_policy::PolicyEngineImpl;
use zero_auth_sessions::{NoOpEventPublisher, SessionService};
use zero_auth_storage::RocksDbStorage;

use crate::config::Config;

/// No-op event publisher for identity core (we'll use integrations for real events)
#[derive(Clone)]
pub struct IdentityNoOpPublisher;

#[async_trait]
impl zero_auth_identity_core::EventPublisher for IdentityNoOpPublisher {
    async fn publish(
        &self,
        _event: zero_auth_identity_core::RevocationEvent,
    ) -> zero_auth_identity_core::Result<()> {
        Ok(())
    }
}

/// Type alias for the policy engine with RocksDB storage
pub type PolicyEngine = PolicyEngineImpl<RocksDbStorage>;

/// Type alias for identity service with standard dependencies
pub type IdentityService = IdentityCoreService<PolicyEngine, IdentityNoOpPublisher, RocksDbStorage>;

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    /// Server configuration for admin/ops endpoints and diagnostics.
    pub config: Config,
    /// Direct storage handle for health checks and admin queries.
    pub storage: Arc<RocksDbStorage>,
    pub identity_service: Arc<IdentityService>,
    pub auth_service: Arc<AuthMethodsService<IdentityService, PolicyEngine, RocksDbStorage>>,
    pub session_service:
        Arc<SessionService<RocksDbStorage, IdentityService, NoOpEventPublisher>>,
    pub integrations_service: Arc<IntegrationsService<RocksDbStorage>>,
    /// Policy engine handle for policy-aware endpoints.
    pub policy_engine: Arc<PolicyEngine>,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self> {
        // Initialize storage
        let storage = Arc::new(RocksDbStorage::open(&config.database_path)?);

        // Initialize policy engine with storage for persistent reputation
        let policy_engine = Arc::new(PolicyEngineImpl::new(Arc::clone(&storage)));

        // Initialize services
        let identity_service = Arc::new(IdentityCoreService::new(
            policy_engine.clone(),
            Arc::new(IdentityNoOpPublisher),
            storage.clone(),
        ));

        // Build OAuth configs from environment
        let oauth_configs = zero_auth_methods::OAuthConfigs {
            google: config
                .oauth_google
                .as_ref()
                .map(|c| zero_auth_methods::OAuthProviderConfig {
                    client_id: c.client_id.clone(),
                    client_secret: c.client_secret.clone(),
                    redirect_uri: c.redirect_uri.clone(),
                }),
            x: config
                .oauth_x
                .as_ref()
                .map(|c| zero_auth_methods::OAuthProviderConfig {
                    client_id: c.client_id.clone(),
                    client_secret: c.client_secret.clone(),
                    redirect_uri: c.redirect_uri.clone(),
                }),
            epic_games: config.oauth_epic.as_ref().map(|c| {
                zero_auth_methods::OAuthProviderConfig {
                    client_id: c.client_id.clone(),
                    client_secret: c.client_secret.clone(),
                    redirect_uri: c.redirect_uri.clone(),
                }
            }),
        };

        let auth_service = Arc::new(AuthMethodsService::with_oauth_configs(
            identity_service.clone(),
            policy_engine.clone(),
            storage.clone(),
            config.service_master_key,
            oauth_configs,
        ));

        let session_service = Arc::new(SessionService::with_event_publisher(
            storage.clone(),
            identity_service.clone(),
            Arc::new(NoOpEventPublisher),
            config.service_master_key,
            config.jwt_issuer.clone(),
            vec![config.jwt_audience.clone()],
            config.access_token_expiry,
            config.refresh_token_expiry,
        ));

        let integrations_service = Arc::new(IntegrationsService::new(storage.clone()));

        // Initialize session service signing keys
        session_service.initialize().await?;

        Ok(AppState {
            config,
            storage,
            identity_service,
            auth_service,
            session_service,
            integrations_service,
            policy_engine,
        })
    }
}
