//! Policy Engine trait and implementation.

use crate::{
    evaluator::PolicyEvaluator,
    rate_limit::RateLimiter,
    types::*,
    errors::Result,
};
use async_trait::async_trait;
use std::sync::Arc;

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
}

/// Policy Engine implementation
pub struct PolicyEngineImpl {
    rate_limiter: Arc<RateLimiter>,
}

impl PolicyEngineImpl {
    /// Create a new policy engine
    pub fn new() -> Self {
        Self {
            rate_limiter: Arc::new(RateLimiter::new()),
        }
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
        // Record in rate limiter
        let key = format!("{}:{:?}", identity_id, operation);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if !success {
            self.rate_limiter.record_failure(&key, 900, 5, current_time); // 15 minutes, 5 attempts
        }

        Ok(())
    }

    async fn get_reputation(&self, _identity_id: uuid::Uuid) -> Result<i32> {
        // Default reputation score
        // Real implementation would look this up from storage
        Ok(0)
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

        let reputation = engine.get_reputation(identity_id).await.unwrap();
        assert_eq!(reputation, 0);
    }
}
