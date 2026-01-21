# Zero-Auth Client

A complete Rust example demonstrating how to integrate with the zero-auth identity system.

## Quick Start

### Prerequisites

1. **Start the Zero-Auth Server**

   Windows:
   ```cmd
   set SERVICE_MASTER_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
   cargo run -p zero-auth-server
   ```

   Linux/macOS:
   ```bash
   export SERVICE_MASTER_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
   cargo run -p zero-auth-server
   ```

2. **Test with the Client**

   ```bash
   # Create an identity with client-side cryptography
   cargo run -p client -- create-identity --device-name "My Device"

   # Authenticate with machine key challenge-response
   cargo run -p client -- login

   # Test protected endpoint (demonstrates token validation)
   cargo run -p client -- test-protected

   # Refresh tokens when they expire
   cargo run -p client -- refresh-token
   ```

### What Gets Created

- **`.session/client-session.json`** - Your session tokens (access + refresh)
- **`.session/credentials.json`** - Your Neural Key and identity info (**keep secure!**)

## Common Commands

```bash
# Identity & Authentication
cargo run -p client -- create-identity [--device-name NAME] [--platform PLATFORM]
cargo run -p client -- login
cargo run -p client -- refresh-token
cargo run -p client -- show-credentials

# Email Authentication
cargo run -p client -- add-email --email EMAIL --password PASSWORD
cargo run -p client -- login-email --email EMAIL --password PASSWORD --machine-id ID

# Machine Management
cargo run -p client -- list-machines
cargo run -p client -- enroll-machine [--device-name NAME] [--platform PLATFORM]
cargo run -p client -- revoke-machine MACHINE_ID [--reason "Lost device"]

# Token Operations
cargo run -p client -- validate-token TOKEN
cargo run -p client -- test-protected
```

For complete command reference, see [REFERENCE.md](REFERENCE.md).

## Key Concepts

### Neural Key
- **Root cryptographic secret** (32 bytes, generated client-side)
- **Never leaves your device** - server never sees it
- **All keys derived** from it using HKDF-SHA256
- **Store securely** in production (OS keychain, HSM)

### Machine Key
- **Per-device key** derived from Neural Key
- **Signing + Encryption** key pairs (Ed25519 + X25519)
- **Capabilities** control what the device can do
- **Can be revoked** independently

### Session Tokens
- **Access Token** (JWT) - 15 minutes, use for API calls
- **Refresh Token** (opaque) - 30 days, get new access token
- **Machine bound** - each session tied to specific device

### Architecture

```
Neural Key (32 bytes, client-only)
    │
    ├─→ Central Signing Key (identity)
    │   └─→ Signs machine enrollments, rotations
    │
    └─→ Machine Keys (per device)
        ├─→ Signing Key (Ed25519)
        │   └─→ Signs challenges, messages
        └─→ Encryption Key (X25519)
            └─→ Encrypts data, sessions
```

## Integration with Your App

### Method 1: Token Introspection (Simplest)

Your app validates tokens by calling zero-auth's introspection endpoint:

```rust
use reqwest;
use serde::Deserialize;

#[derive(Deserialize)]
struct IntrospectResponse {
    active: bool,
    identity_id: Option<String>,
    machine_id: Option<String>,
}

async fn validate_token(token: &str) -> Result<IntrospectResponse, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    
    let response = client
        .post("http://127.0.0.1:8080/v1/auth/introspect")
        .json(&serde_json::json!({
            "token": token,
            "operation_type": "protected"
        }))
        .send()
        .await?;
    
    let token_info: IntrospectResponse = response.json().await?;
    Ok(token_info)
}
```

### Method 2: JWKS Validation (Better Performance)

Your app validates JWTs locally using public keys from the JWKS endpoint:

```rust
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};

#[derive(Deserialize)]
struct Claims {
    sub: String,  // identity_id
    machine_id: String,
    exp: i64,
    iat: i64,
}

// Fetch JWKS once at startup
async fn get_jwks(zero_auth_url: &str) -> Result<jsonwebtoken::jwk::JwkSet> {
    let response = reqwest::get(format!("{}/.well-known/jwks.json", zero_auth_url)).await?;
    let jwks = response.json().await?;
    Ok(jwks)
}

// Validate JWT locally (no network call needed)
fn validate_jwt_local(token: &str, jwks: &jsonwebtoken::jwk::JwkSet) -> Result<Claims> {
    // Find the right key from JWKS (based on kid in token header)
    // Decode and validate the JWT
    // This is faster than introspection because it doesn't hit the network
    Ok(claims)
}
```

### Method 3: Axum Middleware

If your app uses Axum:

```rust
use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};

#[derive(Clone)]
struct AppState {
    zero_auth_url: String,
}

async fn auth_middleware<B>(
    State(state): State<AppState>,
    mut request: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    // Extract token from Authorization header
    let token = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Validate with zero-auth
    let client = reqwest::Client::new();
    let introspect_request = serde_json::json!({
        "token": token,
        "operation_type": "protected"
    });

    let response = client
        .post(format!("{}/v1/auth/introspect", state.zero_auth_url))
        .json(&introspect_request)
        .send()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let token_info: IntrospectResponse = response
        .json()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !token_info.active {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Store identity_id in request extensions for handlers
    request.extensions_mut().insert(token_info.identity_id.unwrap());

    Ok(next.run(request).await)
}
```

## Security Notes

1. **Neural Key Storage** - Use OS keychain in production (Windows Credential Manager, macOS Keychain, Linux Secret Service)
2. **Token Storage** - Store tokens securely, never in version control
3. **HTTPS** - Always use HTTPS in production
4. **Token Expiry** - Implement automatic token refresh
5. **Revocation** - Check token validity before sensitive operations
6. **MFA** - Enable multi-factor authentication for high-security operations

## Troubleshooting

| Error | Solution |
|-------|----------|
| "Failed to load credentials" | Run `create-identity` first |
| "Connection refused" | Make sure zero-auth server is running on port 8080 |
| "Invalid signature" | Credentials may be corrupted, recreate identity |
| "Token expired" | Run `refresh-token` to get a new access token |
| "Failed to load session" | Run `login` first |

## Production Checklist

- [ ] Use HTTPS for zero-auth server
- [ ] Store SERVICE_MASTER_KEY in secrets manager
- [ ] Use proper key storage (OS keychain, not JSON files)
- [ ] Implement automatic token refresh
- [ ] Add rate limiting in your app
- [ ] Set up monitoring for auth failures
- [ ] Configure CORS properly
- [ ] Set up database backup and recovery
- [ ] Test revocation scenarios
- [ ] Implement MFA for sensitive operations

## Project Structure

```
client/
├── Cargo.toml              # Dependencies
├── README.md               # This file (quick start & integration)
├── REFERENCE.md            # Complete command & API reference
└── src/
    ├── main.rs             # Complete example implementation
    ├── commands/           # Command implementations
    ├── storage.rs          # Local storage utilities
    └── types.rs            # Type definitions
```

## Dependencies

- **zero-auth-crypto** - Client-side cryptography (key generation, signing)
- **reqwest** - HTTP client for API calls
- **tokio** - Async runtime
- **serde/serde_json** - JSON serialization
- **uuid** - UUID generation and parsing
- **clap** - Command-line interface
- **colored** - Terminal output formatting

## Next Steps

1. **Test locally** - Run through the quick start commands
2. **Examine source** - Check `src/main.rs` for implementation details
3. **Integrate** - Copy token validation patterns into your app
4. **Secure** - Use proper key storage and HTTPS
5. **Monitor** - Set up logging and error tracking

## Resources

- **Complete Reference:** [REFERENCE.md](REFERENCE.md) - All commands, authentication flows, and API details
- **Example Source:** `src/main.rs` - Complete implementation
- **Zero-Auth README:** `../README.md` - Server documentation
- **API Specification:** See main repository documentation

## Support

For detailed authentication flows, all command options, and API reference, see [REFERENCE.md](REFERENCE.md).
