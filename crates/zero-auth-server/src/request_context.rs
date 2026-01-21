use axum::{
    async_trait,
    extract::{ConnectInfo, FromRequestParts},
    http::{request::Parts, HeaderMap},
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::error::ApiError;
use crate::state::AppState;

/// Extract client IP address with proxy validation
///
/// # Security
///
/// X-Forwarded-For header is only trusted if:
/// 1. A direct connection IP is provided (from trusted source)
/// 2. The direct connection IP is in the trusted_proxies list
/// 3. The X-Forwarded-For header contains valid IP addresses
///
/// Otherwise, uses the direct connection IP or "unknown" as fallback.
///
/// This prevents IP spoofing attacks where an attacker can set arbitrary
/// X-Forwarded-For headers to bypass rate limiting.
pub fn extract_client_ip(
    headers: &HeaderMap,
    direct_ip: Option<IpAddr>,
    trusted_proxies: &[IpAddr],
) -> String {
    // If we have a direct connection IP and it's from a trusted proxy,
    // then we can trust X-Forwarded-For
    if let Some(direct) = direct_ip {
        if trusted_proxies.contains(&direct) {
            // Trust X-Forwarded-For, use the rightmost IP (closest to server, before the proxy)
            if let Some(forwarded) = headers.get("X-Forwarded-For") {
                if let Ok(forwarded_str) = forwarded.to_str() {
                    // Take the last IP in the chain (rightmost)
                    // This is the client IP as seen by our trusted proxy
                    if let Some(ip_str) = forwarded_str.split(',').next_back() {
                        let ip_str = ip_str.trim();
                        // Validate it's a proper IP address
                        if ip_str.parse::<IpAddr>().is_ok() {
                            return ip_str.to_string();
                        }
                    }
                }
            }

            // Fallback to X-Real-IP if X-Forwarded-For is not valid
            if let Some(real_ip) = headers.get("X-Real-IP") {
                if let Ok(ip_str) = real_ip.to_str() {
                    let ip_str = ip_str.trim();
                    if ip_str.parse::<IpAddr>().is_ok() {
                        return ip_str.to_string();
                    }
                }
            }
        }

        // If not from trusted proxy, use direct connection IP
        return direct.to_string();
    }

    // No direct IP available, return unknown
    // In production, direct_ip should always be available from connection metadata
    tracing::warn!("No direct connection IP available for request");
    "unknown".to_string()
}

fn direct_ip_from_parts(parts: &Parts) -> Option<IpAddr> {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip())
}

/// Request context containing metadata about the current request
///
/// This is used for audit logging, rate limiting, and security monitoring.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Client IP address (extracted from connection or X-Forwarded-For)
    pub ip_address: String,

    /// User-Agent string from the request headers
    pub user_agent: String,
}

impl RequestContext {
    /// Create a new request context from request parts
    pub fn from_parts(parts: &Parts, trusted_proxies: &[IpAddr]) -> Self {
        let direct_ip = direct_ip_from_parts(parts);
        let ip_address = extract_client_ip(&parts.headers, direct_ip, trusted_proxies);

        // Extract User-Agent
        let user_agent = parts
            .headers
            .get("User-Agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        Self {
            ip_address,
            user_agent,
        }
    }
}

/// Extractor for request context
///
/// This can be used in any handler to get request metadata
#[async_trait]
impl FromRequestParts<Arc<AppState>> for RequestContext {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        Ok(RequestContext::from_parts(
            parts,
            &state.config.trusted_proxies,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, Request};

    #[test]
    fn test_request_context_extraction() {
        let mut headers = HeaderMap::new();
        // X-Forwarded-For: "client IP, proxy1 IP, proxy2 IP, ..."
        // We use the rightmost IP (10.0.0.1) as it's the closest to our server
        // and harder to spoof than the leftmost IP
        headers.insert(
            "X-Forwarded-For",
            "192.168.1.100, 10.0.0.1".parse().unwrap(),
        );
        headers.insert("User-Agent", "TestClient/1.0".parse().unwrap());

        let req = Request::builder()
            .uri("https://example.com/")
            .body(())
            .unwrap();

        let (mut parts, _) = req.into_parts();
        parts.headers = headers;

        parts
            .extensions
            .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 1], 443))));

        let trusted_proxies = vec!["10.0.0.1".parse().unwrap()];
        let context = RequestContext::from_parts(&parts, &trusted_proxies);

        // Should extract rightmost IP (closest to server)
        assert_eq!(context.ip_address, "10.0.0.1");
        assert_eq!(context.user_agent, "TestClient/1.0");
    }

    #[test]
    fn test_request_context_defaults() {
        let req = Request::builder()
            .uri("https://example.com/")
            .body(())
            .unwrap();

        let (parts, _) = req.into_parts();
        let context = RequestContext::from_parts(&parts, &[]);

        assert_eq!(context.ip_address, "unknown");
        assert_eq!(context.user_agent, "unknown");
    }

    #[test]
    fn test_request_context_trusted_proxy_uses_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "203.0.113.9".parse().unwrap());

        let req = Request::builder()
            .uri("https://example.com/")
            .body(())
            .unwrap();

        let (mut parts, _) = req.into_parts();
        parts.headers = headers;
        parts
            .extensions
            .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 10], 443))));

        let trusted_proxies = vec!["10.0.0.10".parse().unwrap()];
        let context = RequestContext::from_parts(&parts, &trusted_proxies);

        assert_eq!(context.ip_address, "203.0.113.9");
    }
}
