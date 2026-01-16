use anyhow::Result;
use axum::{
    routing::{get, post, delete},
    Router,
};
use std::sync::Arc;
use tower_http::{
    cors::CorsLayer,
    trace::{DefaultMakeSpan, TraceLayer},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod config;
mod error;
mod extractors;
mod middleware;
mod state;

use config::Config;
use state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zero_auth_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env()?;
    let bind_address = config.bind_address;
    tracing::info!("Starting zero-auth server on {}", bind_address);

    // Initialize application state
    let state = Arc::new(AppState::new(config).await?);

    // Build router
    let app = create_router(state);

    // Start server
    let listener = tokio::net::TcpListener::bind(&bind_address).await?;
    tracing::info!("Server listening on {}", bind_address);
    
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health checks
        .route("/health", get(api::health::health_check))
        .route("/ready", get(api::health::readiness_check))
        
        // Identity management
        .route("/v1/identity", post(api::identity::create_identity))
        .route("/v1/identity/:identity_id", get(api::identity::get_identity))
        .route("/v1/identity/freeze", post(api::identity::freeze_identity))
        .route("/v1/identity/unfreeze", post(api::identity::unfreeze_identity))
        .route("/v1/identity/recovery", post(api::identity::recovery_ceremony))
        .route("/v1/identity/rotation", post(api::identity::rotation_ceremony))
        
        // Machine key management
        .route("/v1/machines/enroll", post(api::machines::enroll_machine))
        .route("/v1/machines", get(api::machines::list_machines))
        .route("/v1/machines/:machine_id", delete(api::machines::revoke_machine))
        
        // Authentication
        .route("/v1/auth/challenge", get(api::auth::get_challenge))
        .route("/v1/auth/login/machine", post(api::auth::login_machine))
        .route("/v1/auth/login/email", post(api::auth::login_email))
        .route("/v1/auth/login/wallet", post(api::auth::login_wallet))
        .route("/v1/auth/oauth/:provider", get(api::auth::oauth_initiate))
        .route("/v1/auth/oauth/:provider/callback", post(api::auth::oauth_complete))
        
        // MFA
        .route("/v1/mfa/setup", post(api::mfa::setup_mfa))
        .route("/v1/mfa", delete(api::mfa::disable_mfa))
        
        // Sessions
        .route("/v1/auth/refresh", post(api::sessions::refresh_session))
        .route("/v1/session/revoke", post(api::sessions::revoke_session))
        .route("/v1/session/revoke-all", post(api::sessions::revoke_all_sessions))
        .route("/v1/auth/introspect", post(api::sessions::introspect_token))
        .route("/.well-known/jwks.json", get(api::sessions::jwks_endpoint))
        
        // Integrations
        .route("/v1/integrations/register", post(api::integrations::register_service))
        .route("/v1/events/stream", get(api::integrations::event_stream))
        
        // Add middleware
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default())
        )
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Graceful shutdown initiated");
}
