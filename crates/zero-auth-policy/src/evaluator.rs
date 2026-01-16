//! Policy evaluator logic.

use crate::types::*;

/// Policy evaluator for authorization decisions
pub struct PolicyEvaluator;

impl PolicyEvaluator {
    /// Evaluate a policy context and return a decision
    ///
    /// Evaluation order (as specified in 07-policy-engine.md § 5.1):
    /// 1. Identity frozen check (highest priority)
    /// 2. Identity status check
    /// 3. Machine revocation check
    /// 4. Namespace status check
    /// 5. Operation-specific high-risk checks
    /// 6. Rate limiting
    /// 7. Capability checks
    /// 8. Approval requirements
    pub fn evaluate(context: &PolicyContext) -> PolicyDecision {
        // For now, implement basic allow-all policy
        // Real implementation would check frozen status, rate limits, etc.
        // This is a minimal implementation to get the system working

        let mut decision = PolicyDecision {
            verdict: Verdict::Allow,
            required_factors: Vec::new(),
            required_approvals: 0,
            rate_limit: None,
            audit_tags: vec![
                format!("operation:{:?}", context.operation),
                format!("auth_method:{:?}", context.auth_method),
            ],
            reason: "Policy evaluation passed".to_string(),
        };

        // Check if MFA is required
        if context.operation.requires_mfa() && !context.mfa_verified {
            decision.verdict = Verdict::RequireAdditionalAuth;
            decision.required_factors = vec![AuthFactor::MfaTotp];
            decision.reason = "MFA verification required for this operation".to_string();
            return decision;
        }

        // Check if approvals are required
        let required_approvals = context.operation.required_approvals();
        if required_approvals > 0 {
            decision.required_approvals = required_approvals;
            decision.verdict = Verdict::RequireApproval;
            decision.reason = format!("{} approvals required", required_approvals);
            return decision;
        }

        // Check reputation score
        if context.reputation_score < -50 {
            decision.verdict = Verdict::Deny;
            decision.reason = "Low reputation score".to_string();
            decision.audit_tags.push("low_reputation".to_string());
            return decision;
        }

        // Check recent failed attempts
        if context.recent_failed_attempts >= 5 {
            decision.verdict = Verdict::RateLimited;
            decision.reason = "Too many recent failed attempts".to_string();
            decision.audit_tags.push("failed_attempts".to_string());
            return decision;
        }

        decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        }
    }

    #[test]
    fn test_basic_allow() {
        let context = create_test_context();
        let decision = PolicyEvaluator::evaluate(&context);

        assert_eq!(decision.verdict, Verdict::Allow);
    }

    #[test]
    fn test_mfa_required() {
        let mut context = create_test_context();
        context.operation = Operation::RotateNeuralKey;
        context.mfa_verified = false;

        let decision = PolicyEvaluator::evaluate(&context);

        assert_eq!(decision.verdict, Verdict::RequireAdditionalAuth);
        assert!(decision.required_factors.contains(&AuthFactor::MfaTotp));
    }

    #[test]
    fn test_approvals_required() {
        let mut context = create_test_context();
        context.operation = Operation::RotateNeuralKey;
        context.mfa_verified = true;

        let decision = PolicyEvaluator::evaluate(&context);

        assert_eq!(decision.verdict, Verdict::RequireApproval);
        assert_eq!(decision.required_approvals, 2);
    }

    #[test]
    fn test_low_reputation_denied() {
        let mut context = create_test_context();
        context.reputation_score = -60;

        let decision = PolicyEvaluator::evaluate(&context);

        assert_eq!(decision.verdict, Verdict::Deny);
    }

    #[test]
    fn test_too_many_failed_attempts() {
        let mut context = create_test_context();
        context.recent_failed_attempts = 10;

        let decision = PolicyEvaluator::evaluate(&context);

        assert_eq!(decision.verdict, Verdict::RateLimited);
    }
}
