use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{Request, Response, StatusCode},
    middleware::Next,
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use zero_auth_policy::PolicyEngine;

use crate::request_context::extract_client_ip;
use crate::state::AppState;

fn direct_ip_from_request(req: &Request<Body>) -> Option<IpAddr> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip())
}

/// Request ID middleware for request tracking and logging
///
/// This middleware:
/// - Generates a unique request ID if not provided
/// - Extracts client IP and User-Agent for logging
/// - Logs request start and completion with timing
pub async fn request_id_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    // Generate or extract request ID
    let request_id = req
        .headers()
        .get("X-Request-ID")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();

    let request_id = if request_id.is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        request_id
    };

    // Insert request ID into headers for downstream use
    if let Ok(header_value) = request_id.parse() {
        req.headers_mut().insert("X-Request-ID", header_value);
    } else {
        tracing::warn!("Failed to create header value for request ID");
    }

    // Extract request metadata for logging
    let direct_ip = direct_ip_from_request(&req);
    let ip_address = extract_client_ip(req.headers(), direct_ip, &state.config.trusted_proxies);

    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    tracing::info!(
        request_id = %request_id,
        method = %req.method(),
        uri = %req.uri(),
        ip = %ip_address,
        user_agent = %user_agent,
        "Request started"
    );

    let start = Instant::now();
    let mut response = next.run(req).await;
    let elapsed = start.elapsed();

    // Add request ID to response headers
    if let Ok(header_value) = request_id.parse() {
        response.headers_mut().insert("X-Request-ID", header_value);
    }

    tracing::info!(
        request_id = %request_id,
        status = %response.status(),
        elapsed_ms = elapsed.as_millis(),
        "Request completed"
    );

    Ok(response)
}

/// Rate limiting middleware
///
/// Enforces rate limits based on IP address to prevent abuse.
/// This provides a first line of defense before authentication.
pub async fn rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    let direct_ip = direct_ip_from_request(&req);
    let ip_address = extract_client_ip(req.headers(), direct_ip, &state.config.trusted_proxies);

    // Check IP-based rate limit using the policy engine
    match state.policy_engine.check_ip_rate_limit(ip_address.as_str()) {
        Some(rate_limit) => {
            tracing::trace!(
                ip = %ip_address,
                remaining = rate_limit.remaining,
                "Rate limit check passed"
            );

            // Add rate limit headers to response
            let mut response = next.run(req).await;
            let headers = response.headers_mut();

            // Add rate limit headers (log error if header creation fails)
            if let Ok(value) = rate_limit.max_attempts.to_string().parse() {
                headers.insert("X-RateLimit-Limit", value);
            }
            if let Ok(value) = rate_limit.remaining.to_string().parse() {
                headers.insert("X-RateLimit-Remaining", value);
            }
            if let Ok(value) = rate_limit.reset_at.to_string().parse() {
                headers.insert("X-RateLimit-Reset", value);
            }

            Ok(response)
        }
        None => {
            // Rate limit exceeded
            tracing::warn!(ip = %ip_address, "Rate limit exceeded");

            // Return 429 Too Many Requests
            let mut response = Response::new(Body::from("Rate limit exceeded"));
            *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;

            // Add Retry-After header (suggest 60 seconds)
            if let Ok(value) = "60".parse() {
                response.headers_mut().insert("Retry-After", value);
            }

            Ok(response)
        }
    }
}
