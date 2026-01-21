impl<I, P, S> AuthMethodsService<I, P, S>
where
    I: IdentityCore,
    P: PolicyEngine,
    S: Storage,
{
    async fn load_active_identity(&self, identity_id: Uuid) -> Result<Identity> {
        let identity = self.identity_core.get_identity(identity_id).await?;
        if identity.status == IdentityStatus::Frozen {
            return Err(AuthMethodsError::IdentityFrozen {
                identity_id,
                reason: identity.frozen_reason,
            });
        }

        Ok(identity)
    }

    async fn evaluate_oauth_login(
        &self,
        identity: &Identity,
        identity_id: Uuid,
        machine_id: Uuid,
        ip_address: String,
        user_agent: String,
    ) -> Result<zero_auth_policy::PolicyDecision> {
        let reputation_score = self.policy.get_reputation(identity_id).await.unwrap_or(50);
        let context = PolicyContext {
            identity_id,
            machine_id: Some(machine_id),
            namespace_id: identity.identity_id,
            auth_method: zero_auth_policy::AuthMethod::OAuth,
            mfa_verified: false,
            operation: Operation::Login,
            resource: None,
            ip_address,
            user_agent,
            timestamp: current_timestamp(),
            reputation_score,
            recent_failed_attempts: 0,
            // Entity states checked separately in auth flow
            identity_status: None,
            machine_revoked: None,
            machine_capabilities: None,
            namespace_active: None,
        };

        self.policy.evaluate(context).await.map_err(AuthMethodsError::Policy)
    }

    fn build_oauth_auth_result(
        &self,
        identity: &Identity,
        identity_id: Uuid,
        machine_id: Uuid,
    ) -> AuthResult {
        AuthResult {
            identity_id,
            machine_id,
            namespace_id: identity.identity_id,
            mfa_verified: false,
            auth_method: AuthMethod::OAuth,
            warning: Some("Consider enrolling a real device for enhanced security".to_string()),
        }
    }

    async fn update_existing_oauth_link(
        &self,
        link_key: &String,
    ) -> Result<Option<OAuthLink>> {
        let existing_link: Option<OAuthLink> = self.storage.get(CF_OAUTH_LINKS, link_key).await?;
        let Some(existing_link) = existing_link else {
            return Ok(None);
        };

        if existing_link.revoked {
            return Err(AuthMethodsError::Other(
                "OAuth link was revoked".to_string(),
            ));
        }

        let mut updated_link = existing_link.clone();
        updated_link.last_auth_at = current_timestamp();
        self.storage
            .put(CF_OAUTH_LINKS, link_key, &updated_link)
            .await?;

        info!(
            "OAuth link already exists for identity {}",
            existing_link.identity_id
        );

        Ok(Some(updated_link))
    }

    fn require_oauth_identity_id(&self, oauth_state: &OAuthState) -> Result<Uuid> {
        oauth_state.identity_id.ok_or_else(|| {
            AuthMethodsError::Other("No identity_id in OAuth state".to_string())
        })
    }

    fn build_new_oauth_link(
        &self,
        provider: OAuthProvider,
        identity_id: Uuid,
        provider_user_id: String,
        provider_email: Option<String>,
        email_verified: Option<bool>,
        display_name: Option<String>,
    ) -> OAuthLink {
        OAuthLink {
            link_id: Uuid::new_v4(),
            identity_id,
            provider,
            provider_user_id,
            provider_email,
            email_verified,
            display_name,
            linked_at: current_timestamp(),
            last_auth_at: current_timestamp(),
            revoked: false,
            revoked_at: None,
        }
    }

    async fn store_oauth_link(&self, link_key: &String, link: &OAuthLink) -> Result<()> {
        self.storage.put(CF_OAUTH_LINKS, link_key, link).await?;
        Ok(())
    }

    async fn store_oauth_identity_index(
        &self,
        identity_id: Uuid,
        provider: OAuthProvider,
        link_id: Uuid,
    ) -> Result<()> {
        let identity_index_key = format!("{}:{}", identity_id, provider.as_str());
        self.storage
            .put(CF_OAUTH_LINKS_BY_IDENTITY, &identity_index_key, &link_id)
            .await?;
        Ok(())
    }
}

fn state_hash_for_log(state: &str) -> String {
    let hash = blake3_hash(state.as_bytes());
    hex::encode(&hash[..8])
}
