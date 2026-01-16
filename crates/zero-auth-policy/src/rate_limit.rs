//! Rate limiting implementation.

use crate::types::RateLimit;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Rate limiter for tracking attempts per identity/IP
pub struct RateLimiter {
    limits: Arc<Mutex<HashMap<String, LimitState>>>,
}

#[derive(Debug, Clone)]
struct LimitState {
    attempts: u32,
    window_start: u64,
    window_seconds: u64,
    max_attempts: u32,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new() -> Self {
        Self {
            limits: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check if a key is rate limited
    ///
    /// Returns `Some(RateLimit)` with remaining attempts, or `None` if rate limited
    pub fn check(
        &self,
        key: &str,
        window_seconds: u64,
        max_attempts: u32,
        current_time: u64,
    ) -> Option<RateLimit> {
        let mut limits = self.limits.lock().unwrap();

        let state = limits.entry(key.to_string()).or_insert(LimitState {
            attempts: 0,
            window_start: current_time,
            window_seconds,
            max_attempts,
        });

        // Check if window has expired
        if current_time >= state.window_start + state.window_seconds {
            // Reset window
            state.window_start = current_time;
            state.attempts = 0;
        }

        // Check if rate limited
        if state.attempts >= state.max_attempts {
            return None;
        }

        // Increment attempts
        state.attempts += 1;

        Some(RateLimit {
            window_seconds: state.window_seconds,
            max_attempts: state.max_attempts,
            remaining: state.max_attempts - state.attempts,
            reset_at: state.window_start + state.window_seconds,
        })
    }

    /// Record a failed attempt
    pub fn record_failure(&self, key: &str, window_seconds: u64, max_attempts: u32, current_time: u64) {
        let mut limits = self.limits.lock().unwrap();

        let state = limits.entry(key.to_string()).or_insert(LimitState {
            attempts: 0,
            window_start: current_time,
            window_seconds,
            max_attempts,
        });

        // Check if window has expired
        if current_time >= state.window_start + state.window_seconds {
            // Reset window
            state.window_start = current_time;
            state.attempts = 0;
        }

        state.attempts += 1;
    }

    /// Reset rate limit for a key
    pub fn reset(&self, key: &str) {
        let mut limits = self.limits.lock().unwrap();
        limits.remove(key);
    }

    /// Clear all rate limits (for testing)
    #[cfg(test)]
    pub fn clear(&self) {
        let mut limits = self.limits.lock().unwrap();
        limits.clear();
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_allow() {
        let limiter = RateLimiter::new();
        let key = "test-key";

        let result = limiter.check(key, 60, 5, 1000);
        assert!(result.is_some());

        let limit = result.unwrap();
        assert_eq!(limit.remaining, 4);
    }

    #[test]
    fn test_rate_limit_exceed() {
        let limiter = RateLimiter::new();
        let key = "test-key";

        // Use up all attempts
        for _ in 0..5 {
            let _ = limiter.check(key, 60, 5, 1000);
        }

        // Should be rate limited
        let result = limiter.check(key, 60, 5, 1000);
        assert!(result.is_none());
    }

    #[test]
    fn test_rate_limit_window_reset() {
        let limiter = RateLimiter::new();
        let key = "test-key";

        // Use up all attempts
        for _ in 0..5 {
            let _ = limiter.check(key, 60, 5, 1000);
        }

        // Should be rate limited
        assert!(limiter.check(key, 60, 5, 1000).is_none());

        // Move past window
        let result = limiter.check(key, 60, 5, 1061);
        assert!(result.is_some());

        let limit = result.unwrap();
        assert_eq!(limit.remaining, 4);
    }

    #[test]
    fn test_rate_limit_reset() {
        let limiter = RateLimiter::new();
        let key = "test-key";

        // Use up all attempts
        for _ in 0..5 {
            let _ = limiter.check(key, 60, 5, 1000);
        }

        // Reset
        limiter.reset(key);

        // Should be allowed
        let result = limiter.check(key, 60, 5, 1000);
        assert!(result.is_some());
    }

    #[test]
    fn test_record_failure() {
        let limiter = RateLimiter::new();
        let key = "test-key";

        limiter.record_failure(key, 60, 5, 1000);
        limiter.record_failure(key, 60, 5, 1000);

        let result = limiter.check(key, 60, 5, 1000);
        assert!(result.is_some());

        let limit = result.unwrap();
        assert_eq!(limit.remaining, 2); // 2 failures + 1 check = 3 attempts used
    }
}
