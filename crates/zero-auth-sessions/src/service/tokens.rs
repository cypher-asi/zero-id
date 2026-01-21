//! Token issuance and verification for the session service.

use crate::{errors::*, types::*};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;
use zero_auth_identity_core::IdentityCore;
use zero_auth_storage::{column_families::*, Storage};

use super::{EventPublisher, SessionService};

/// Generate random bytes of the specified length
pub fn generate_random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// URL-safe base64 encoding without padding
pub fn base64_url_encode(data: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(data)
}

/// SHA-256 hash
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

impl<S: Storage, I: IdentityCore, E: EventPublisher> SessionService<S, I, E> {
    /// Issue a JWT access token
    pub(super) async fn issue_access_token(
        &self,
        session: &Session,
        mfa_verified: bool,
        capabilities: Vec<String>,
        scope: Vec<String>,
    ) -> Result<String> {
        // Get machine to determine revocation epoch
        let machine = self
            .identity_core
            .get_machine_key(session.machine_id)
            .await?;

        let claims =
            self.build_token_claims(session, mfa_verified, capabilities, scope, machine.epoch);

        self.sign_jwt_with_key(&claims).await
    }

    /// Generate a refresh token
    pub(super) async fn generate_refresh_token(
        &self,
        session_id: Uuid,
        machine_id: Uuid,
        token_family_id: Uuid,
        generation: u32,
    ) -> Result<String> {
        // Generate 32 random bytes
        let token_bytes = generate_random_bytes::<32>();
        let refresh_token = base64_url_encode(&token_bytes);

        // Hash the token for storage
        let token_hash = sha256(refresh_token.as_bytes());

        // Create token record
        let record = RefreshTokenRecord {
            token_hash,
            session_id,
            machine_id,
            token_family_id,
            generation,
            created_at: current_timestamp(),
            expires_at: current_timestamp() + self.refresh_token_ttl,
            used: false,
            used_at: None,
            revoked: false,
            revoked_at: None,
            revoked_reason: None,
        };

        // Store in database
        self.storage
            .put(CF_REFRESH_TOKENS, &token_hash, &record)
            .await?;

        // Also index by token family
        let family_key = self.make_family_key(token_family_id, generation);
        self.storage
            .put(CF_REFRESH_TOKENS_BY_FAMILY, &family_key, &token_hash)
            .await?;

        Ok(refresh_token)
    }

    /// Verify JWT token
    pub(super) async fn verify_jwt_internal(&self, token: &str) -> Result<TokenClaims> {
        // Step 1: Parse header WITHOUT verification
        let header = jsonwebtoken::decode_header(token)?;

        // Step 2: STRICT algorithm check
        if header.alg != Algorithm::EdDSA {
            return Err(SessionError::InvalidAlgorithm {
                found: format!("{:?}", header.alg),
            });
        }

        // Step 3: Get kid
        let kid = header.kid.ok_or(SessionError::MissingKeyId)?;

        // Step 4: Lookup signing key
        let keys = self.signing_keys.read().await;
        let signing_key = keys
            .get(&kid)
            .ok_or_else(|| SessionError::UnknownKeyId(kid.clone()))?;

        // Step 5: Check key status
        let can_verify = match signing_key.status {
            KeyStatus::Active => true,
            KeyStatus::Rotating => {
                let now = current_timestamp();
                let rotation_started = signing_key.expires_at.unwrap_or(now);
                now < rotation_started + 3600
            }
            KeyStatus::Retired => false,
        };

        if !can_verify {
            return Err(SessionError::KeyRetired {
                kid,
                retired_at: signing_key.expires_at,
            });
        }

        // Step 6: Configure strict validation
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&self.default_audience);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        // Step 7: Verify signature
        let public_key_b64 = base64_url_encode(&signing_key.public_key);
        let decoding_key = DecodingKey::from_ed_components(&public_key_b64)
            .map_err(|e| SessionError::Other(format!("Failed to create decoding key: {}", e)))?;
        let token_data = decode::<TokenClaims>(token, &decoding_key, &validation)?;

        Ok(token_data.claims)
    }

    fn build_token_claims(
        &self,
        session: &Session,
        mfa_verified: bool,
        capabilities: Vec<String>,
        scope: Vec<String>,
        revocation_epoch: u64,
    ) -> TokenClaims {
        let now = current_timestamp();
        let exp = now + self.access_token_ttl;

        TokenClaims {
            iss: self.issuer.clone(),
            sub: session.identity_id.to_string(),
            aud: self.default_audience.clone(),
            iat: now,
            exp,
            nbf: now,
            jti: Uuid::new_v4().to_string(),
            machine_id: session.machine_id.to_string(),
            namespace_id: session.namespace_id.to_string(),
            session_id: session.session_id.to_string(),
            mfa_verified,
            capabilities,
            scope,
            revocation_epoch,
        }
    }

    async fn sign_jwt_with_key(&self, claims: &TokenClaims) -> Result<String> {
        let current_kid = self.current_key_id.read().await.clone();
        let keys = self.signing_keys.read().await;
        let signing_key = keys
            .get(&current_kid)
            .ok_or_else(|| SessionError::Other("No active signing key".to_string()))?;

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(current_kid);

        let private_key_bytes = zero_auth_crypto::decrypt_jwt_signing_key(
            &self.service_master_key,
            &signing_key.private_key_encrypted,
            &signing_key.private_key_nonce,
            &signing_key.key_id,
            signing_key.epoch,
        )?;

        if private_key_bytes.len() != 32 {
            return Err(SessionError::Other(
                "Invalid private key length after decryption".to_string(),
            ));
        }

        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&private_key_bytes);

        let pkcs8_prefix: &[u8] = &[
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];

        let mut pkcs8_der = Vec::with_capacity(48);
        pkcs8_der.extend_from_slice(pkcs8_prefix);
        pkcs8_der.extend_from_slice(&private_key);

        let encoding_key = EncodingKey::from_ed_der(&pkcs8_der);
        let token = encode(&header, claims, &encoding_key)?;

        use zeroize::Zeroize;
        private_key.zeroize();

        Ok(token)
    }
}
