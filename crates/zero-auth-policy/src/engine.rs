//! Policy Engine trait and implementation.

use crate::{errors::Result, evaluator::PolicyEvaluator, rate_limit::RateLimiter, types::*};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Policy Engine trait for authorization and rate limiting
#[async_trait]
pub trait PolicyEngine: Send + Sync {
    /// Evaluate policy for an operation
    async fn evaluate(&self, context: PolicyContext) -> Result<PolicyDecision>;

    /// Record operation attempt (for rate limiting and reputation)
    async fn record_attempt(
        &self,
        identity_id: uuid::Uuid,
        operation: Operation,
        success: bool,
    ) -> Result<()>;

    /// Get reputation score for an identity
    async fn get_reputation(&self, identity_id: uuid::Uuid) -> Result<i32>;

    /// Check rate limit for an IP address
    /// Returns Some(RateLimit) if allowed, None if rate limited
    fn check_ip_rate_limit(&self, ip_address: &str) -> Option<RateLimit>;

    /// Check rate limit for an identity
    /// Returns Some(RateLimit) if allowed, None if rate limited
    fn check_identity_rate_limit(&self, identity_id: uuid::Uuid) -> Option<RateLimit>;
}

/// Reputation tracker for identities
#[derive(Debug, Clone, Default)]
struct ReputationScore {
    /// Current reputation score (0-100, higher is better)
    score: i32,
    /// Total successful attempts
    successful_attempts: u32,
    /// Total failed attempts
    failed_attempts: u32,
}

/// Policy Engine implementation
pub struct PolicyEngineImpl {
    rate_limiter: Arc<RateLimiter>,
    /// In-memory reputation tracking (in production, use persistent storage)
    reputation: Arc<RwLock<HashMap<uuid::Uuid, ReputationScore>>>,
}

impl PolicyEngineImpl {
    /// Create a new policy engine
    pub fn new() -> Self {
        Self {
            rate_limiter: Arc::new(RateLimiter::new()),
            reputation: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Calculate reputation score based on success/failure history
    fn calculate_reputation(successful: u32, failed: u32) -> i32 {
        if successful == 0 && failed == 0 {
            return 50; // Neutral starting score
        }

        let total = successful + failed;
        let success_rate = (successful as f64) / (total as f64);

        // Scale to 0-100, with penalties for high failure rates
        let base_score = (success_rate * 100.0) as i32;

        // Apply penalties for absolute number of failures
        let failure_penalty = (failed as i32).min(50);

        (base_score - failure_penalty).clamp(0, 100)
    }
}

impl Default for PolicyEngineImpl {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PolicyEngine for PolicyEngineImpl {
    async fn evaluate(&self, context: PolicyContext) -> Result<PolicyDecision> {
        // Use the evaluator to make the decision
        let decision = PolicyEvaluator::evaluate(&context);

        Ok(decision)
    }

    async fn record_attempt(
        &self,
        identity_id: uuid::Uuid,
        operation: Operation,
        success: bool,
    ) -> Result<()> {
        // Update reputation score
        let reputation_score = {
            let mut reputation_map = self.reputation.write().unwrap();
            let rep = reputation_map.entry(identity_id).or_default();

            if success {
                rep.successful_attempts += 1;
            } else {
                rep.failed_attempts += 1;
            }

            // Recalculate score
            rep.score = Self::calculate_reputation(rep.successful_attempts, rep.failed_attempts);
            rep.score // Return score before dropping lock
        }; // Lock released here

        // Record in rate limiter
        let key = format!("{}:{:?}", identity_id, operation);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if !success {
            self.rate_limiter.record_failure(&key, 900, 5, current_time); // 15 minutes, 5 attempts
        }

        // Log the attempt
        tracing::debug!(
            identity_id = %identity_id,
            operation = ?operation,
            success = success,
            reputation_score,
            "Recorded operation attempt"
        );

        Ok(())
    }

    async fn get_reputation(&self, identity_id: uuid::Uuid) -> Result<i32> {
        let reputation_map = self.reputation.read().unwrap();
        Ok(reputation_map
            .get(&identity_id)
            .map(|rep| rep.score)
            .unwrap_or(50)) // Default to neutral score (50/100) if no history
    }

    fn check_ip_rate_limit(&self, ip_address: &str) -> Option<RateLimit> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // IP rate limiting: 100 requests per minute (configurable per endpoint type)
        self.rate_limiter.check(
            &format!("ip:{}", ip_address),
            60,  // 1 minute window
            100, // 100 requests per minute
            current_time,
        )
    }

    fn check_identity_rate_limit(&self, identity_id: uuid::Uuid) -> Option<RateLimit> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Identity rate limiting: 1000 requests per hour
        self.rate_limiter.check(
            &format!("identity:{}", identity_id),
            3600, // 1 hour window
            1000, // 1000 requests per hour
            current_time,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_policy_engine_evaluate() {
        let engine = PolicyEngineImpl::new();

        let context = PolicyContext {
            identity_id: uuid::Uuid::new_v4(),
            machine_id: Some(uuid::Uuid::new_v4()),
            namespace_id: uuid::Uuid::new_v4(),
            auth_method: AuthMethod::MachineKey,
            mfa_verified: true,
            operation: Operation::Login,
            resource: None,
            ip_address: "127.0.0.1".to_string(),
            user_agent: "test-agent".to_string(),
            timestamp: 1705320000,
            reputation_score: 0,
            recent_failed_attempts: 0,
        };

        let decision = engine.evaluate(context).await.unwrap();
        assert_eq!(decision.verdict, Verdict::Allow);
    }

    #[tokio::test]
    async fn test_record_attempt() {
        let engine = PolicyEngineImpl::new();
        let identity_id = uuid::Uuid::new_v4();

        // Should not error
        engine
            .record_attempt(identity_id, Operation::Login, true)
            .await
            .unwrap();

        engine
            .record_attempt(identity_id, Operation::Login, false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_get_reputation() {
        let engine = PolicyEngineImpl::new();
        let identity_id = uuid::Uuid::new_v4();

        // Should return neutral score (50) for new identity with no history
        let reputation = engine.get_reputation(identity_id).await.unwrap();
        assert_eq!(reputation, 50);

        // Test that recording attempts updates reputation
        engine
            .record_attempt(identity_id, Operation::Login, true)
            .await
            .unwrap();
        engine
            .record_attempt(identity_id, Operation::Login, true)
            .await
            .unwrap();
        let updated_reputation = engine.get_reputation(identity_id).await.unwrap();
        assert!(
            updated_reputation >= 50,
            "Reputation should improve after successful attempts"
        );

        // Test that failures decrease reputation
        engine
            .record_attempt(identity_id, Operation::Login, false)
            .await
            .unwrap();
        engine
            .record_attempt(identity_id, Operation::Login, false)
            .await
            .unwrap();
        engine
            .record_attempt(identity_id, Operation::Login, false)
            .await
            .unwrap();
        let decreased_reputation = engine.get_reputation(identity_id).await.unwrap();
        assert!(
            decreased_reputation < updated_reputation,
            "Reputation should decrease after failures"
        );
    }
}
