# Zero-Auth Client - Complete Reference

Complete command reference and authentication flow documentation.

## Table of Contents

- [Command Reference](#command-reference)
- [Authentication Flows](#authentication-flows)
- [Email Authentication](#email-authentication)
- [Machine Management](#machine-management)
- [API Endpoints](#api-endpoints)
- [Security Best Practices](#security-best-practices)

---

## Command Reference

### Global Options

All commands support:
```bash
-s, --server URL    # Use different server (default: http://127.0.0.1:8080)
```

### Identity & Authentication

#### `create-identity`

Creates a new identity with client-side Neural Key generation.

```bash
cargo run -p client -- create-identity [OPTIONS]
```

**Options:**
- `-d, --device-name <NAME>` - Device name (default: "Example Client Device")
- `-p, --platform <PLATFORM>` - Device platform (default: "rust-app")

**Examples:**
```bash
# With defaults
cargo run -p client -- create-identity

# Custom device info
cargo run -p client -- create-identity -d "Main Laptop" -p "linux"
```

**What happens:**
- Generates Neural Key (32 bytes, stays on client)
- Derives central signing key from Neural Key
- Derives machine signing/encryption keys
- Creates cryptographic proof of ownership
- Registers identity with server
- Saves credentials to `.session/credentials.json`

**Output:** Creates `.session/credentials.json` containing your Neural Key (keep secure!)

---

#### `login`

Authenticate using machine key challenge-response.

```bash
cargo run -p client -- login
```

**What happens:**
- Requests a challenge from the server
- Signs the challenge with your machine private key
- Submits the signature to complete authentication
- Receives JWT access token and refresh token
- Saves session to `.session/client-session.json`

**Prerequisites:** Must have credentials (run `create-identity` first)

---

#### `refresh-token`

Get a new access token using refresh token.

```bash
cargo run -p client -- refresh-token
```

**What happens:**
- Uses refresh token from session
- Gets new access token with fresh 15-minute lifetime
- Updates `.session/client-session.json`

**Prerequisites:** Must have active session (run `login` first)

---

#### `show-credentials`

Display stored credentials (Neural Key is hidden).

```bash
cargo run -p client -- show-credentials
```

**Output:**
- Identity ID
- Machine ID
- Device name/platform
- Public keys
- Session info (if active)

---

### Email Authentication

#### `add-email`

Add email/password credential to your identity.

```bash
cargo run -p client -- add-email --email EMAIL --password PASSWORD
```

**Options:**
- `-e, --email <EMAIL>` - Email address
- `-p, --password <PASSWORD>` - Password (must meet complexity requirements)

**Password Requirements:**
- 12-128 characters long
- At least one uppercase letter (A-Z)
- At least one lowercase letter (a-z)
- At least one digit (0-9)
- At least one special character (!@#$%^&* etc.)

**Examples:**
```bash
cargo run -p client -- add-email -e "alice@example.com" -p "SecurePass123!"
```

**Prerequisites:** Must be logged in (have active session)

---

#### `login-email`

Login using email and password.

```bash
cargo run -p client -- login-email --email EMAIL --password PASSWORD --machine-id ID
```

**Options:**
- `-e, --email <EMAIL>` - Email address
- `-p, --password <PASSWORD>` - Password
- `-m, --machine-id <ID>` - Machine ID to use for session

**Examples:**
```bash
# First, get your machine_id
cargo run -p client -- list-machines

# Then login
cargo run -p client -- login-email -e "alice@example.com" -p "SecurePass123!" -m <machine-id>
```

**What happens:**
- Authenticates using email/password instead of machine keys
- Creates a new session using the specified machine
- Saves session to `.session/client-session.json`

---

### Machine Management

#### `list-machines`

List all enrolled machines for your identity.

```bash
cargo run -p client -- list-machines
```

**Output for each machine:**
- Machine ID
- Device name and platform
- Created timestamp
- Last used timestamp
- Revocation status

**Prerequisites:** Must be authenticated

---

#### `enroll-machine`

Enroll a new machine/device to your identity.

```bash
cargo run -p client -- enroll-machine [OPTIONS]
```

**Options:**
- `-d, --device-name <NAME>` - Device name (default: "New Device")
- `-p, --platform <PLATFORM>` - Device platform (default: "rust-app")

**Examples:**
```bash
cargo run -p client -- enroll-machine -d "My Phone" -p "android"
```

**What happens:**
1. Generates new machine ID
2. Derives machine keys from Neural Key
3. Creates authorization signature
4. Registers with server
5. New device can authenticate

**Prerequisites:**
- Must be authenticated
- Must have Neural Key (credentials file)

---

#### `revoke-machine`

Revoke a machine (lost, stolen, or retired device).

```bash
cargo run -p client -- revoke-machine <MACHINE_ID> [OPTIONS]
```

**Arguments:**
- `<MACHINE_ID>` - UUID of machine to revoke

**Options:**
- `-r, --reason <REASON>` - Revocation reason (default: "Manual revocation")

**Examples:**
```bash
# Get machine ID first
cargo run -p client -- list-machines

# Revoke with reason
cargo run -p client -- revoke-machine <machine-id> -r "Lost device"
```

**What happens:**
1. Machine marked as revoked
2. All sessions terminated
3. Cannot authenticate anymore
4. Revocation event published

**Common reasons:**
- "Lost device"
- "Stolen device"
- "Sold/disposed"
- "Security incident"
- "Upgrading device"

**Prerequisites:**
- Must be authenticated
- Cannot revoke your current machine

---

### Token Operations

#### `validate-token`

Validate a JWT token via introspection endpoint.

```bash
cargo run -p client -- validate-token <TOKEN>
```

**Output:**
- Token validity status
- Identity ID, Machine ID
- MFA verification status
- Capabilities
- Expiration time

---

#### `test-protected`

Test authentication flow (demonstrates token validation).

```bash
cargo run -p client -- test-protected
```

**What happens:**
- Validates current session token
- Shows what your app would see
- Demonstrates identity extraction from token

**Prerequisites:** Must have active session

---

## Authentication Flows

### Flow 1: Machine Key Authentication (Primary)

The most secure method using cryptographic challenge-response.

```rust
use zero_auth_crypto::{derive_machine_keypair, sign_message, NeuralKey};

async fn login_with_machine_key(
    neural_key: &NeuralKey,
    identity_id: Uuid,
    machine_id: Uuid,
) -> Result<SessionTokens> {
    let client = reqwest::Client::new();
    
    // Step 1: Request challenge
    let challenge_response = client
        .get(format!(
            "http://127.0.0.1:8080/v1/auth/challenge?machine_id={}",
            machine_id
        ))
        .send()
        .await?
        .json::<ChallengeResponse>()
        .await?;
    
    // Step 2: Decode challenge
    let challenge_bytes = base64::decode(&challenge_response.challenge)?;
    
    // Step 3: Derive machine keypair from Neural Key
    let machine_keypair = derive_machine_keypair(
        neural_key,
        &identity_id,
        &machine_id,
        0,  // epoch
        MachineKeyCapabilities::FULL_DEVICE,
    )?;
    
    // Step 4: Sign challenge
    let signature = sign_message(
        machine_keypair.signing_key_pair(),
        &challenge_bytes
    );
    
    // Step 5: Submit signature
    let login_response = client
        .post("http://127.0.0.1:8080/v1/auth/login/machine")
        .json(&json!({
            "challenge_id": challenge_response.challenge_id,
            "machine_id": machine_id,
            "signature": hex::encode(&signature)
        }))
        .send()
        .await?
        .json::<LoginResponse>()
        .await?;
    
    Ok(SessionTokens {
        access_token: login_response.access_token,
        refresh_token: login_response.refresh_token,
        session_id: login_response.session_id,
        expires_at: login_response.expires_at,
    })
}
```

**Run:** `cargo run -p client -- login`

---

### Flow 2: Email/Password Authentication

```rust
async fn login_with_email(
    email: &str,
    password: &str,
    machine_id: Uuid,
) -> Result<SessionTokens> {
    let client = reqwest::Client::new();
    
    let response = client
        .post("http://127.0.0.1:8080/v1/auth/login/email")
        .json(&json!({
            "email": email,
            "password": password,
            "machine_id": machine_id,
            "mfa_code": None::<String>
        }))
        .send()
        .await?;
    
    let login_response: LoginResponse = response.json().await?;
    
    Ok(SessionTokens {
        access_token: login_response.access_token,
        refresh_token: login_response.refresh_token,
        session_id: login_response.session_id,
        expires_at: login_response.expires_at,
    })
}
```

**Run:** `cargo run -p client -- login-email -e "alice@example.com" -p "Password123!" -m <machine-id>`

---

### Flow 3: Token Refresh

```rust
async fn refresh_access_token(
    refresh_token: &str,
    session_id: Uuid,
    machine_id: Uuid,
) -> Result<SessionTokens> {
    let client = reqwest::Client::new();
    
    let response = client
        .post("http://127.0.0.1:8080/v1/auth/refresh")
        .json(&json!({
            "refresh_token": refresh_token,
            "session_id": session_id,
            "machine_id": machine_id
        }))
        .send()
        .await?;
    
    let refresh_response: RefreshResponse = response.json().await?;
    
    Ok(SessionTokens {
        access_token: refresh_response.access_token,
        refresh_token: refresh_response.refresh_token,
        session_id,
        expires_at: refresh_response.expires_at,
    })
}
```

**Run:** `cargo run -p client -- refresh-token`

---

### Flow 4: Machine Enrollment

```rust
use zero_auth_crypto::{
    derive_machine_keypair,
    canonicalize_enrollment_message,
    sign_message,
    derive_central_public_key,
    MachineKeyCapabilities,
};

async fn enroll_new_machine(
    neural_key: &NeuralKey,
    identity_id: Uuid,
    access_token: &str,
    device_name: &str,
    device_platform: &str,
) -> Result<Uuid> {
    // Step 1: Generate new machine ID
    let machine_id = Uuid::new_v4();
    
    // Step 2: Derive machine keypair from Neural Key
    let machine_keypair = derive_machine_keypair(
        neural_key,
        &identity_id,
        &machine_id,
        0,
        MachineKeyCapabilities::FULL_DEVICE,
    )?;
    
    let signing_pk = machine_keypair.signing_public_key();
    let encryption_pk = machine_keypair.encryption_public_key();
    
    // Step 3: Get central signing key
    let (_, central_signing_keypair) = derive_central_public_key(neural_key, &identity_id)?;
    
    // Step 4: Create enrollment message
    let created_at = chrono::Utc::now().timestamp() as u64;
    let namespace_id = identity_id;
    
    let message = canonicalize_enrollment_message(
        &machine_id,
        &namespace_id,
        &signing_pk,
        &encryption_pk,
        MachineKeyCapabilities::FULL_DEVICE.bits(),
        created_at,
    );
    
    // Step 5: Sign with central signing key
    let authorization_signature = sign_message(&central_signing_keypair, &message);
    
    // Step 6: Send enrollment request
    let client = reqwest::Client::new();
    let response = client
        .post("http://127.0.0.1:8080/v1/machines/enroll")
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&json!({
            "machine_id": machine_id,
            "namespace_id": namespace_id,
            "signing_public_key": hex::encode(&signing_pk),
            "encryption_public_key": hex::encode(&encryption_pk),
            "capabilities": ["FULL_DEVICE"],
            "device_name": device_name,
            "device_platform": device_platform,
            "authorization_signature": hex::encode(&authorization_signature)
        }))
        .send()
        .await?;
    
    Ok(machine_id)
}
```

**Run:** `cargo run -p client -- enroll-machine -d "Phone" -p "android"`

---

## Email Authentication

### Adding Email Credential

Before you can login with email, you must add an email credential to your identity:

**Step 1: Login with machine key**
```bash
cargo run -p client -- login
```

**Step 2: Add email credential**
```bash
cargo run -p client -- add-email -e "alice@example.com" -p "SecurePass123!"
```

### Password Requirements

All passwords must meet these requirements:

- **Length**: 12-128 characters
- **Uppercase**: At least one uppercase letter (A-Z)
- **Lowercase**: At least one lowercase letter (a-z)
- **Digits**: At least one number (0-9)
- **Special chars**: At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)

**Examples of valid passwords:**
- `Password123!`
- `MySecure@Pass456`
- `Zero#Auth2026`
- `C0mpl3x!PassW0rd`

### Server-Side Hashing

```rust
// Server hashes passwords with Argon2id
pub async fn attach_email_credential(
    &self,
    identity_id: Uuid,
    email: String,
    password: String,
) -> Result<()> {
    // 1. Validate email and password
    validate_email(&email)?;
    validate_password(&password)?;
    
    // 2. Hash password with Argon2id
    let salt = generate_salt();  // 32 bytes random
    let password_hash = argon2id_hash(&password, &salt)?;
    
    // 3. Store credential
    storage.put("auth_credentials", &email, &EmailCredential {
        identity_id,
        email: email.to_lowercase(),
        password_hash,
        created_at: now(),
    }).await?;
    
    Ok(())
}
```

### Complete Workflow

```bash
# Step 1: Create identity
cargo run -p client -- create-identity --device-name "Laptop"

# Step 2: Login with machine key
cargo run -p client -- login

# Step 3: Add email credential
cargo run -p client -- add-email -e "alice@example.com" -p "Password123!"

# Step 4: List machines to get machine_id
cargo run -p client -- list-machines

# Step 5: Login with email
cargo run -p client -- login-email -e "alice@example.com" -p "Password123!" -m <machine-id>
```

---

## Machine Management

### Machine Key Capabilities

```rust
// Available capabilities:
MachineKeyCapabilities::AUTHENTICATE     // Can authenticate (login)
MachineKeyCapabilities::SIGN             // Can sign messages
MachineKeyCapabilities::ENCRYPT          // Can encrypt data
MachineKeyCapabilities::SVK_UNWRAP       // Can unwrap secret vault keys
MachineKeyCapabilities::MLS_MESSAGING    // Can use MLS messaging
MachineKeyCapabilities::VAULT_OPERATIONS // Can perform vault operations
MachineKeyCapabilities::FULL_DEVICE      // All capabilities (typical device)
MachineKeyCapabilities::SERVICE_MACHINE  // Service/bot machine

// Combine capabilities:
let caps = MachineKeyCapabilities::AUTHENTICATE 
         | MachineKeyCapabilities::SIGN
         | MachineKeyCapabilities::ENCRYPT;
```

### Listing Machines

```rust
async fn list_machines(
    access_token: &str,
    namespace_id: Option<Uuid>,
) -> Result<Vec<MachineInfo>> {
    let client = reqwest::Client::new();
    
    let mut url = "http://127.0.0.1:8080/v1/machines".to_string();
    if let Some(ns_id) = namespace_id {
        url.push_str(&format!("?namespace_id={}", ns_id));
    }
    
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await?
        .json::<ListMachinesResponse>()
        .await?;
    
    Ok(response.machines)
}
```

**Run:** `cargo run -p client -- list-machines`

### Revoking Machines

```rust
async fn revoke_machine(
    access_token: &str,
    machine_id: Uuid,
    reason: &str,
) -> Result<()> {
    let client = reqwest::Client::new();
    
    client
        .delete(format!(
            "http://127.0.0.1:8080/v1/machines/{}",
            machine_id
        ))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&json!({
            "reason": reason
        }))
        .send()
        .await?;
    
    Ok(())
}
```

**What happens when you revoke:**
1. Machine marked as revoked
2. All active sessions terminated
3. Cannot re-authenticate
4. Revocation event published
5. Action is permanent (must re-enroll to add back)

**Run:** `cargo run -p client -- revoke-machine <machine-id> -r "Lost device"`

---

## API Endpoints

| Operation | Method | Endpoint | Auth Required |
|-----------|--------|----------|---------------|
| Create Identity | POST | `/v1/identity` | No |
| Add Email | POST | `/v1/credentials/email` | Yes |
| Get Challenge | GET | `/v1/auth/challenge` | No |
| Login (Machine) | POST | `/v1/auth/login/machine` | No |
| Login (Email) | POST | `/v1/auth/login/email` | No |
| Refresh Token | POST | `/v1/auth/refresh` | No (needs refresh_token) |
| Token Introspection | POST | `/v1/auth/introspect` | No |
| Enroll Machine | POST | `/v1/machines/enroll` | Yes |
| List Machines | GET | `/v1/machines` | Yes |
| Revoke Machine | DELETE | `/v1/machines/:id` | Yes |
| Get JWKS | GET | `/.well-known/jwks.json` | No |
| Health Check | GET | `/health` | No |

---

## Security Best Practices

### 1. Neural Key Storage

**Development:**
- JSON file in `.session/credentials.json`

**Production:**
- **Windows**: Windows Credential Manager
- **macOS**: Keychain
- **Linux**: Secret Service / libsecret
- **Hardware**: HSM or TPM
- **Never**: Plain text files, version control, network transmission

### 2. Token Management

**Access Tokens:**
- Store in memory only
- 15-minute lifetime
- Include in `Authorization: Bearer <token>` header
- Clear on logout

**Refresh Tokens:**
- Store in secure storage
- 30-day lifetime
- Use to get new access tokens
- Rotate on each refresh

**Best practices:**
- Implement automatic token refresh
- Clear all tokens on logout
- Don't log tokens
- Use HTTPS only

### 3. Machine Keys

**Lifecycle:**
- Derive from Neural Key
- Enroll with appropriate capabilities
- Monitor for unauthorized devices
- Revoke lost/stolen immediately
- Rotate periodically (6-12 months)

**Revocation scenarios:**
- Lost device
- Stolen device
- Sold/disposed device
- Security incident
- Employee departure

### 4. Authentication

**Machine Key Auth (Preferred):**
- Cryptographic challenge-response
- No password to remember
- Resistant to phishing
- Offline key derivation

**Email/Password Auth (Backup):**
- Strong passwords (12+ chars)
- Password requirements enforced
- Argon2id hashing
- Rate limiting recommended

**MFA:**
- Enable for sensitive operations
- TOTP-based (Google Authenticator, Authy)
- Backup codes for recovery
- Required for high-security accounts

### 5. Recovery Procedures

**Before you need it:**
- Set up multiple machines
- Store recovery codes offline
- Document recovery procedures
- Test recovery process

**Neural Key backup:**
- Encrypted backup on USB drive
- Paper backup in safe
- Split across multiple locations
- Never in cloud unencrypted

### 6. Production Deployment

**Infrastructure:**
- Use HTTPS everywhere
- Store master key in secrets manager (AWS Secrets Manager, HashiCorp Vault)
- Enable audit logging
- Set up monitoring and alerting
- Configure rate limiting
- Regular security updates

**Application:**
- Validate tokens server-side
- Implement proper error handling
- Don't expose internal errors
- Log security events
- Monitor for suspicious activity

---

## Troubleshooting

### Common Errors

**"Failed to load credentials"**
- **Cause:** No credentials file exists
- **Solution:** Run `create-identity` first
- **File:** `.session/credentials.json`

**"Connection refused"**
- **Cause:** Server not running
- **Solution:** Start server on port 8080
- **Command:** `cargo run -p zero-auth-server`

**"Invalid signature"**
- **Cause:** Wrong Neural Key or corrupted credentials
- **Solution:** Delete credentials and recreate identity
- **Files:** `.session/credentials.json`, `.session/client-session.json`

**"Token expired"**
- **Cause:** Access token lifetime exceeded (15 minutes)
- **Solution:** Run `refresh-token`
- **Prevention:** Implement automatic refresh

**"Failed to load session"**
- **Cause:** No session file exists
- **Solution:** Run `login` first
- **File:** `.session/client-session.json`

**"Machine not found"**
- **Cause:** Machine may have been revoked
- **Solution:** Enroll a new machine
- **Command:** `enroll-machine`

**"Email already registered"**
- **Cause:** Email linked to another identity
- **Solution:** Use different email or recover that identity

**Password validation errors**
- **Cause:** Password doesn't meet complexity requirements
- **Solution:** Use password with 12+ chars, uppercase, lowercase, digit, special character
- **Example:** `Password123!`

**"MFA required"**
- **Cause:** MFA enabled but no code provided
- **Solution:** Provide MFA code in login request

**"Challenge expired"**
- **Cause:** Challenge not used within 60 seconds
- **Solution:** Request new challenge and complete login faster

### Debug Mode

```bash
# Enable debug logging
RUST_LOG=debug cargo run -p client -- login

# Verbose output
cargo run -p client -- -v login
```

### Inspecting Tokens

**Decode JWT payload (requires jq):**

Linux/macOS:
```bash
TOKEN=$(cat .session/client-session.json | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
echo $TOKEN | cut -d. -f2 | base64 -d | jq .
```

**Online tool:**
- Copy token from `.session/client-session.json`
- Paste into https://jwt.io
- Inspect claims

---

## Typical Workflows

### Initial Setup
```bash
cargo run -p client -- create-identity -d "Main PC"
cargo run -p client -- login
cargo run -p client -- test-protected
```

### Add Email Backup
```bash
cargo run -p client -- login
cargo run -p client -- add-email -e "alice@example.com" -p "Password123!"
```

### Multi-Device Setup
```bash
# On Device A
cargo run -p client -- create-identity -d "Laptop"
cargo run -p client -- login
cargo run -p client -- enroll-machine -d "Phone" -p "android"

# Copy credentials file to Device B, then:
cargo run -p client -- login
```

### Lost Device Response
```bash
cargo run -p client -- login
cargo run -p client -- list-machines
cargo run -p client -- revoke-machine <lost-machine-id> -r "Lost device"
```

### Daily Usage
```bash
# Morning: Login
cargo run -p client -- login

# Use access token in your app...

# After 15+ minutes: Refresh
cargo run -p client -- refresh-token

# Continue working...
```

---

## Files Created

### `.session/credentials.json`
```json
{
  "neural_key_hex": "[SENSITIVE - 64 hex chars]",
  "identity_id": "uuid",
  "machine_id": "uuid",
  "central_public_key": "hex",
  "machine_signing_public_key": "hex",
  "machine_encryption_public_key": "hex",
  "device_name": "Device Name",
  "device_platform": "platform"
}
```

**⚠️ CRITICAL:** Contains your Neural Key. Keep secure! Never commit to version control.

### `.session/client-session.json`
```json
{
  "access_token": "jwt...",
  "refresh_token": "opaque...",
  "session_id": "uuid",
  "expires_at": "2026-01-19T12:00:00Z"
}
```

**Temporary:** Can be safely deleted, just login again.

---

## See Also

- **README.md** - Quick start and integration guide
- **src/main.rs** - Complete example implementation
- **../README.md** - Zero-Auth server documentation
