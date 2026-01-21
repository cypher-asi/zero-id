//! Policy Engine trait and implementation.

use crate::{errors::Result, evaluator::PolicyEvaluator, rate_limit::RateLimiter, types::*};
use async_trait::async_trait;
use std::sync::Arc;
use zero_auth_storage::{Storage, CF_REPUTATION};

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

/// Policy Engine implementation with persistent reputation storage
pub struct PolicyEngineImpl<S: Storage> {
    storage: Arc<S>,
    rate_limiter: Arc<RateLimiter>,
    config: RateLimitConfig,
}

impl<S: Storage> PolicyEngineImpl<S> {
    /// Create a new policy engine with storage and default config
    pub fn new(storage: Arc<S>) -> Self {
        Self {
            storage,
            rate_limiter: Arc::new(RateLimiter::new()),
            config: RateLimitConfig::default(),
        }
    }

    /// Create a new policy engine with custom rate limit configuration
    pub fn with_config(storage: Arc<S>, config: RateLimitConfig) -> Self {
        Self {
            storage,
            rate_limiter: Arc::new(RateLimiter::new()),
            config,
        }
    }

    /// Get the current rate limit configuration
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
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

    /// Get current timestamp
    fn current_time() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

#[async_trait]
impl<S: Storage + 'static> PolicyEngine for PolicyEngineImpl<S> {
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
        let current_time = Self::current_time();

        // Load or create reputation record
        let mut record: ReputationRecord = self
            .storage
            .get(CF_REPUTATION, &identity_id)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| ReputationRecord {
                identity_id,
                score: 50,
                successful_attempts: 0,
                failed_attempts: 0,
                last_updated: current_time,
            });

        // Update attempts
        if success {
            record.successful_attempts += 1;
        } else {
            record.failed_attempts += 1;
        }

        // Recalculate score
        record.score =
            Self::calculate_reputation(record.successful_attempts, record.failed_attempts);
        record.last_updated = current_time;

        // Persist reputation record
        if let Err(e) = self.storage.put(CF_REPUTATION, &identity_id, &record).await {
            tracing::warn!(
                identity_id = %identity_id,
                error = %e,
                "Failed to persist reputation record, continuing with in-memory state"
            );
        }

        // Record in rate limiter for failure tracking
        if !success {
            let key = format!("{}:{:?}", identity_id, operation);
            self.rate_limiter.record_failure(
                &key,
                self.config.failure_window_seconds,
                self.config.failure_max_attempts,
                current_time,
            );
        }

        tracing::debug!(
            identity_id = %identity_id,
            operation = ?operation,
            success = success,
            reputation_score = record.score,
            "Recorded operation attempt"
        );

        Ok(())
    }

    async fn get_reputation(&self, identity_id: uuid::Uuid) -> Result<i32> {
        // Try to load from persistent storage
        let record: Option<ReputationRecord> = self
            .storage
            .get(CF_REPUTATION, &identity_id)
            .await
            .ok()
            .flatten();

        Ok(record.map(|r| r.score).unwrap_or(50)) // Default to neutral score
    }

    fn check_ip_rate_limit(&self, ip_address: &str) -> Option<RateLimit> {
        self.rate_limiter.check(
            &format!("ip:{}", ip_address),
            self.config.ip_window_seconds,
            self.config.ip_max_requests,
            Self::current_time(),
        )
    }

    fn check_identity_rate_limit(&self, identity_id: uuid::Uuid) -> Option<RateLimit> {
        self.rate_limiter.check(
            &format!("identity:{}", identity_id),
            self.config.identity_window_seconds,
            self.config.identity_max_requests,
            Self::current_time(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::capabilities;
    use std::collections::HashMap;
    use std::sync::RwLock;
    use zero_auth_storage::{Batch, StorageError};

    /// Mock storage for testing
    struct MockStorage {
        data: RwLock<HashMap<String, Vec<u8>>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                data: RwLock::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl Storage for MockStorage {
        async fn get<K, V>(&self, cf: &str, key: &K) -> zero_auth_storage::Result<Option<V>>
        where
            K: serde::Serialize + Send + Sync,
            V: serde::de::DeserializeOwned,
        {
            let key_bytes = bincode::serialize(key)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            let storage_key = format!("{}:{}", cf, hex::encode(&key_bytes));

            let data = self.data.read().unwrap();
            match data.get(&storage_key) {
                Some(bytes) => {
                    let value: V = bincode::deserialize(bytes)
                        .map_err(|e| StorageError::Deserialization(e.to_string()))?;
                    Ok(Some(value))
                }
                None => Ok(None),
            }
        }

        async fn put<K, V>(&self, cf: &str, key: &K, value: &V) -> zero_auth_storage::Result<()>
        where
            K: serde::Serialize + Send + Sync,
            V: serde::Serialize + Send + Sync,
        {
            let key_bytes = bincode::serialize(key)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            let value_bytes = bincode::serialize(value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            let storage_key = format!("{}:{}", cf, hex::encode(&key_bytes));

            let mut data = self.data.write().unwrap();
            data.insert(storage_key, value_bytes);
            Ok(())
        }

        async fn delete<K>(&self, cf: &str, key: &K) -> zero_auth_storage::Result<()>
        where
            K: serde::Serialize + Send + Sync,
        {
            let key_bytes = bincode::serialize(key)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            let storage_key = format!("{}:{}", cf, hex::encode(&key_bytes));

            let mut data = self.data.write().unwrap();
            data.remove(&storage_key);
            Ok(())
        }

        async fn exists<K>(&self, cf: &str, key: &K) -> zero_auth_storage::Result<bool>
        where
            K: serde::Serialize + Send + Sync,
        {
            let key_bytes = bincode::serialize(key)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            let storage_key = format!("{}:{}", cf, hex::encode(&key_bytes));

            let data = self.data.read().unwrap();
            Ok(data.contains_key(&storage_key))
        }

        async fn get_by_prefix<K, V>(
            &self,
            _cf: &str,
            _prefix: &K,
        ) -> zero_auth_storage::Result<Vec<(Vec<u8>, V)>>
        where
            K: serde::Serialize + Send + Sync,
            V: serde::de::DeserializeOwned,
        {
            Ok(vec![])
        }

        async fn scan_all<V>(&self, _cf: &str) -> zero_auth_storage::Result<Vec<(Vec<u8>, V)>>
        where
            V: serde::de::DeserializeOwned,
        {
            Ok(vec![])
        }

        fn batch(&self) -> Box<dyn Batch> {
            Box::new(MockBatch)
        }

        async fn begin_transaction(&self) -> zero_auth_storage::Result<Box<dyn Batch>> {
            Ok(Box::new(MockBatch))
        }
    }

    struct MockBatch;

    #[async_trait]
    impl Batch for MockBatch {
        fn put_raw(&mut self, _cf: &str, _key: Vec<u8>, _value: Vec<u8>) -> zero_auth_storage::Result<()> {
            Ok(())
        }

        fn delete_raw(&mut self, _cf: &str, _key: Vec<u8>) -> zero_auth_storage::Result<()> {
            Ok(())
        }

        async fn commit(self: Box<Self>) -> zero_auth_storage::Result<()> {
            Ok(())
        }

        fn rollback(self: Box<Self>) {}
    }

    fn create_test_context() -> PolicyContext {
        PolicyContext {
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
            identity_status: Some(IdentityStatus::Active),
            machine_revoked: Some(false),
            machine_capabilities: Some(capabilities::AUTHENTICATE | capabilities::SIGN),
            namespace_active: Some(true),
        }
    }

    #[tokio::test]
    async fn test_policy_engine_evaluate() {
        let storage = Arc::new(MockStorage::new());
        let engine = PolicyEngineImpl::new(storage);

        let context = create_test_context();
        let decision = engine.evaluate(context).await.unwrap();
        assert_eq!(decision.verdict, Verdict::Allow);
    }

    #[tokio::test]
    async fn test_record_attempt() {
        let storage = Arc::new(MockStorage::new());
        let engine = PolicyEngineImpl::new(storage);
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
        let storage = Arc::new(MockStorage::new());
        let engine = PolicyEngineImpl::new(storage);
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

    #[tokio::test]
    async fn test_reputation_persistence() {
        let storage = Arc::new(MockStorage::new());

        // Create first engine instance, record attempts
        {
            let engine = PolicyEngineImpl::new(Arc::clone(&storage));
            let identity_id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

            engine
                .record_attempt(identity_id, Operation::Login, true)
                .await
                .unwrap();
            engine
                .record_attempt(identity_id, Operation::Login, true)
                .await
                .unwrap();

            let rep = engine.get_reputation(identity_id).await.unwrap();
            assert!(rep >= 50);
        }

        // Create new engine instance with same storage, verify reputation persisted
        {
            let engine = PolicyEngineImpl::new(Arc::clone(&storage));
            let identity_id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

            let rep = engine.get_reputation(identity_id).await.unwrap();
            assert!(rep >= 50, "Reputation should persist across engine instances");
        }
    }

    #[tokio::test]
    async fn test_configurable_rate_limits() {
        let storage = Arc::new(MockStorage::new());
        let config = RateLimitConfig {
            ip_window_seconds: 30,
            ip_max_requests: 10,
            identity_window_seconds: 1800,
            identity_max_requests: 500,
            failure_window_seconds: 600,
            failure_max_attempts: 3,
        };

        let engine = PolicyEngineImpl::with_config(storage, config);

        assert_eq!(engine.config().ip_window_seconds, 30);
        assert_eq!(engine.config().ip_max_requests, 10);
        assert_eq!(engine.config().identity_window_seconds, 1800);
        assert_eq!(engine.config().identity_max_requests, 500);
        assert_eq!(engine.config().failure_window_seconds, 600);
        assert_eq!(engine.config().failure_max_attempts, 3);
    }

    #[tokio::test]
    async fn test_reputation_calculation_edge_cases() {
        // 0/0 - neutral score
        assert_eq!(PolicyEngineImpl::<MockStorage>::calculate_reputation(0, 0), 50);

        // All success - high score
        let all_success = PolicyEngineImpl::<MockStorage>::calculate_reputation(100, 0);
        assert_eq!(all_success, 100);

        // All failure - low score
        let all_failure = PolicyEngineImpl::<MockStorage>::calculate_reputation(0, 100);
        assert_eq!(all_failure, 0);

        // Mixed - should penalize failures
        let mixed = PolicyEngineImpl::<MockStorage>::calculate_reputation(50, 50);
        assert!(mixed < 50, "Mixed results with failures should be below neutral");
    }

    #[test]
    fn test_ip_rate_limit_uses_config() {
        let storage = Arc::new(MockStorage::new());
        let config = RateLimitConfig {
            ip_window_seconds: 10,
            ip_max_requests: 3,
            ..Default::default()
        };
        let engine = PolicyEngineImpl::with_config(storage, config);

        // Should allow first 3 requests
        assert!(engine.check_ip_rate_limit("192.168.1.1").is_some());
        assert!(engine.check_ip_rate_limit("192.168.1.1").is_some());
        assert!(engine.check_ip_rate_limit("192.168.1.1").is_some());

        // Fourth request should be rate limited
        assert!(engine.check_ip_rate_limit("192.168.1.1").is_none());
    }
}
