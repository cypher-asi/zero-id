use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use zero_auth_storage::RocksDbStorage;
use zero_auth_identity_core::IdentityCoreService;
use zero_auth_auth_methods::AuthMethodsService;
use zero_auth_sessions::{SessionService, NoOpEventPublisher};
use zero_auth_integrations::IntegrationsService;
use zero_auth_policy::PolicyEngineImpl;

use crate::config::Config;

/// No-op event publisher for identity core (we'll use integrations for real events)
#[derive(Clone)]
pub struct IdentityNoOpPublisher;

#[async_trait]
impl zero_auth_identity_core::EventPublisher for IdentityNoOpPublisher {
    async fn publish(&self, _event: zero_auth_identity_core::RevocationEvent) -> zero_auth_identity_core::Result<()> {
        Ok(())
    }
}

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    /// Server configuration (for future use in handlers)
    #[allow(dead_code)]
    pub config: Config,
    /// Direct storage access (for future advanced queries)
    #[allow(dead_code)]
    pub storage: Arc<RocksDbStorage>,
    pub identity_service: Arc<IdentityCoreService<PolicyEngineImpl, IdentityNoOpPublisher, RocksDbStorage>>,
    pub auth_service: Arc<AuthMethodsService<IdentityCoreService<PolicyEngineImpl, IdentityNoOpPublisher, RocksDbStorage>, PolicyEngineImpl, RocksDbStorage>>,
    pub session_service: Arc<SessionService<RocksDbStorage, IdentityCoreService<PolicyEngineImpl, IdentityNoOpPublisher, RocksDbStorage>, NoOpEventPublisher>>,
    pub integrations_service: Arc<IntegrationsService<RocksDbStorage>>,
    /// Policy engine for direct access (for future policy evaluation in handlers)
    #[allow(dead_code)]
    pub policy_engine: Arc<PolicyEngineImpl>,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self> {
        // Initialize storage
        let storage = Arc::new(RocksDbStorage::open(&config.database_path)?);
        
        // Initialize policy engine
        let policy_engine = Arc::new(PolicyEngineImpl::new());
        
        // Initialize services
        let identity_service = Arc::new(IdentityCoreService::new(
            policy_engine.clone(),
            Arc::new(IdentityNoOpPublisher),
            storage.clone(),
        ));
        
        let auth_service = Arc::new(AuthMethodsService::new(
            identity_service.clone(),
            policy_engine.clone(),
            storage.clone(),
        ));
        
        let session_service = Arc::new(SessionService::new(
            storage.clone(),
            identity_service.clone(),
            config.service_master_key,
            config.jwt_issuer.clone(),
            vec![config.jwt_audience.clone()],
        ));
        
        let integrations_service = Arc::new(IntegrationsService::new(storage.clone()));

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
