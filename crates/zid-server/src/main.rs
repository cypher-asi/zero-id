use anyhow::Result;
use axum::{
    http::{HeaderValue, Method},
    routing::{delete, get, patch, post},
    Router,
};
use std::net::SocketAddr;
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
mod request_context;
mod state;

use config::Config;
use state::AppState;

/// CLI arguments parsed from command line
struct CliArgs {
    generate_key: bool,
    help: bool,
}

fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    CliArgs {
        generate_key: args.iter().any(|a| a == "--generate-key" || a == "-g"),
        help: args.iter().any(|a| a == "--help" || a == "-h"),
    }
}

fn print_help() {
    eprintln!(
        r#"zid-server - Zero-ID Identity Server

USAGE:
    cargo run -p zid-server [OPTIONS]

OPTIONS:
    -g, --generate-key   Generate a random SERVICE_MASTER_KEY for this session
                         (sets RUN_MODE=dev automatically)
    -h, --help           Print this help

ENVIRONMENT VARIABLES:
    RUN_MODE                      dev or prod (default: prod)
    SERVICE_MASTER_KEY            64-char hex key (required in prod)
    BIND_ADDRESS                  Listen address (default: 127.0.0.1:9999)
    DATABASE_PATH                 RocksDB path (default: ./data/zid.db)
    RUST_LOG                      Log level (default: zid_server=debug)

EXAMPLES:
    # Development with auto-generated key
    cargo run -p zid-server -- --generate-key

    # Production with explicit key
    SERVICE_MASTER_KEY=<your-key> cargo run -p zid-server --release
"#
    );
}

/// Build CORS layer with configured allowed origins
fn build_cors_layer(allowed_origins: &[String]) -> CorsLayer {
    use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};

    let mut cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::DELETE,
            Method::PUT,
            Method::OPTIONS,
        ])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
        .allow_credentials(true);

    // Add each allowed origin
    for origin in allowed_origins {
        if let Ok(header_value) = origin.parse::<HeaderValue>() {
            cors = cors.allow_origin(header_value);
        } else {
            tracing::warn!("Invalid CORS origin: {}", origin);
        }
    }

    cors
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args();

    if args.help {
        print_help();
        return Ok(());
    }

    // If --generate-key is passed, generate a key and set env vars
    if args.generate_key {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let key_hex = hex::encode(key);

        std::env::set_var("RUN_MODE", "dev");
        std::env::set_var("SERVICE_MASTER_KEY", &key_hex);

        eprintln!("=== zid Dev Server ===");
        eprintln!();
        eprintln!("Generated SERVICE_MASTER_KEY for this session:");
        eprintln!("  {}", key_hex);
        eprintln!();
        eprintln!("Note: Tokens from this session won't work after restart.");
        eprintln!();
    }

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zid_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env()?;
    let bind_address = config.bind_address;
    tracing::info!("Starting zid server on {}", bind_address);

    // Initialize application state
    let state = Arc::new(AppState::new(config).await?);

    // Build router
    let app = create_router(state);

    // Start server
    let listener = tokio::net::TcpListener::bind(&bind_address).await?;
    tracing::info!("Server listening on {}", bind_address);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health checks
        .route("/health", get(api::health::health_check))
        .route("/ready", get(api::health::readiness_check))
        // Identity management (self-sovereign creation)
        .route("/v1/identity", post(api::identity::create_identity))
        .route(
            "/v1/identity/:identity_id",
            get(api::identity::get_identity),
        )
        // Identity creation (managed tier)
        .route("/v1/identity/email", post(api::identity_creation::create_email_identity))
        .route("/v1/identity/oauth/:provider", post(api::identity_creation::initiate_oauth_identity))
        .route("/v1/identity/oauth/:provider/callback", post(api::identity_creation::complete_oauth_identity))
        .route("/v1/identity/wallet/challenge", post(api::identity_creation::initiate_wallet_identity))
        .route("/v1/identity/wallet/verify", post(api::identity_creation::complete_wallet_identity))
        // Identity tier and upgrade
        .route("/v1/identity/tier", get(api::identity_creation::get_tier_status))
        .route("/v1/identity/upgrade", post(api::identity_creation::upgrade_identity))
        // Ceremonies (self-sovereign only)
        .route("/v1/identity/freeze", post(api::identity::freeze_identity))
        .route(
            "/v1/identity/unfreeze",
            post(api::identity::unfreeze_identity),
        )
        .route(
            "/v1/identity/recovery",
            post(api::identity::recovery_ceremony),
        )
        .route(
            "/v1/identity/rotation",
            post(api::identity::rotation_ceremony),
        )
        // Machine key management
        .route("/v1/machines/enroll", post(api::machines::enroll_machine))
        .route("/v1/machines", get(api::machines::list_machines))
        .route(
            "/v1/machines/:machine_id",
            delete(api::machines::revoke_machine),
        )
        // Namespace management
        .route("/v1/namespaces", post(api::namespaces::create_namespace))
        .route("/v1/namespaces", get(api::namespaces::list_namespaces))
        .route(
            "/v1/namespaces/:namespace_id",
            get(api::namespaces::get_namespace),
        )
        .route(
            "/v1/namespaces/:namespace_id",
            patch(api::namespaces::update_namespace),
        )
        .route(
            "/v1/namespaces/:namespace_id/deactivate",
            post(api::namespaces::deactivate_namespace),
        )
        .route(
            "/v1/namespaces/:namespace_id/reactivate",
            post(api::namespaces::reactivate_namespace),
        )
        .route(
            "/v1/namespaces/:namespace_id",
            delete(api::namespaces::delete_namespace),
        )
        // Namespace members
        .route(
            "/v1/namespaces/:namespace_id/members",
            get(api::namespaces::list_members),
        )
        .route(
            "/v1/namespaces/:namespace_id/members",
            post(api::namespaces::add_member),
        )
        .route(
            "/v1/namespaces/:namespace_id/members/:identity_id",
            patch(api::namespaces::update_member),
        )
        .route(
            "/v1/namespaces/:namespace_id/members/:identity_id",
            delete(api::namespaces::remove_member),
        )
        // Authentication
        .route("/v1/auth/challenge", get(api::auth::get_challenge))
        .route("/v1/auth/login/machine", post(api::auth::login_machine))
        .route("/v1/auth/login/email", post(api::auth::login_email))
        .route(
            "/v1/auth/login/wallet",
            post(api::auth_wallet::login_wallet),
        )
        .route("/v1/auth/oauth/:provider", get(api::auth::oauth_initiate))
        .route(
            "/v1/auth/oauth/:provider/callback",
            post(api::auth::oauth_complete),
        )
        // MFA
        .route("/v1/mfa/setup", post(api::mfa::setup_mfa))
        .route("/v1/mfa", delete(api::mfa::disable_mfa))
        // Credentials
        .route(
            "/v1/credentials/email",
            post(api::credentials::add_email_credential),
        )
        .route(
            "/v1/credentials/oauth/:provider",
            post(api::credentials::initiate_oauth_link),
        )
        .route(
            "/v1/credentials/oauth/:provider/callback",
            post(api::credentials::complete_oauth_link),
        )
        // Sessions
        .route("/v1/auth/refresh", post(api::sessions::refresh_session))
        .route("/v1/session/revoke", post(api::sessions::revoke_session))
        .route(
            "/v1/session/revoke-all",
            post(api::sessions::revoke_all_sessions),
        )
        .route("/v1/auth/introspect", post(api::sessions::introspect_token))
        .route("/.well-known/jwks.json", get(api::sessions::jwks_endpoint))
        // Integrations
        .route(
            "/v1/integrations/register",
            post(api::integrations::register_service),
        )
        .route("/v1/events/stream", get(api::integrations::event_stream))
        // Add middleware (order matters: last added = first executed)
        .layer(TraceLayer::new_for_http().make_span_with(DefaultMakeSpan::default()))
        .layer(build_cors_layer(&state.config.cors_allowed_origins))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::request_id_middleware,
        ))
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
