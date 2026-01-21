//! Common utility functions for zero-auth cryptographic operations.

use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current Unix timestamp in seconds.
///
/// This is the single source of truth for timestamp generation across the zero-auth system.
///
/// # Panics
///
/// Panics if the system time is set before the Unix epoch (January 1, 1970).
/// This is extremely unlikely in production but can happen if the system clock is misconfigured.
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time is before Unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_timestamp() {
        let ts1 = current_timestamp();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let ts2 = current_timestamp();

        assert!(ts2 >= ts1, "Timestamp should increase with time");
        assert!(
            ts1 > 1_600_000_000,
            "Timestamp should be reasonable (after Sep 2020)"
        );
    }
}
