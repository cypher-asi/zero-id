/*!
 * Authentication commands
 */

use anyhow::{Context, Result};
use base64::Engine;
use colored::*;
use std::io::{self, Write};
use uuid::Uuid;
use zero_auth_crypto::{
    derive_machine_keypair, sign_message, MachineKeyCapabilities, NeuralKey, NeuralShard,
};

use crate::storage::{
    is_legacy_credentials, load_and_reconstruct_neural_key, load_credentials,
    migrate_legacy_credentials, prompt_neural_shard, prompt_passphrase, save_session,
};
use crate::types::{ChallengeResponse, ClientCredentials, LoginResponse, SessionData};

pub async fn login(server: &str) -> Result<()> {
    println!("{}", "=== Machine Key Authentication ===".bold().cyan());

    // Check for legacy credentials and migrate if needed
    if is_legacy_credentials() {
        println!(
            "\n{}",
            "Legacy credentials detected. Migration required.".yellow()
        );
        let passphrase = prompt_passphrase("Enter passphrase: ")?;
        let user_shards = migrate_legacy_credentials(&passphrase)?;
        display_migration_shards(&user_shards)?;

        println!(
            "\n{}",
            "Please run 'login' again with one of your new Neural Shards.".yellow()
        );
        return Ok(());
    }

    // Load credentials to get IDs (no passphrase needed yet)
    let credentials = load_credentials()?;
    print_credentials_info(&credentials.identity_id, &credentials.machine_id);

    let challenge_data = request_challenge(server, &credentials.machine_id).await?;

    // Prompt for passphrase and user shard to reconstruct Neural Key
    println!(
        "\n{}",
        "Step 3: Reconstructing Neural Key from shards...".yellow()
    );
    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let user_shard = prompt_neural_shard()?;

    let (neural_key, _) = load_and_reconstruct_neural_key(&passphrase, &user_shard)?;
    println!("{}", "✓ Neural Key reconstructed in memory".green());

    let signature = sign_challenge(&challenge_data, &credentials, &neural_key)?;
    let login_result = submit_login(
        server,
        &challenge_data.challenge_id,
        &credentials.machine_id,
        &signature,
    )
    .await?;

    print_login_success(&login_result);
    save_session_data(&login_result)?;
    Ok(())
}

fn display_migration_shards(shards: &[NeuralShard; 3]) -> Result<()> {
    println!();
    println!(
        "{}",
        "╔═══════════════════════════════════════════════════════════════════════╗"
            .red()
            .bold()
    );
    println!(
        "{}",
        "║                    YOUR NEW NEURAL SHARDS                             ║"
            .red()
            .bold()
    );
    println!(
        "{}",
        "║                                                                       ║"
            .red()
    );
    println!(
        "{}",
        "║  You need your PASSPHRASE + ONE of these shards to log in.            ║"
            .white()
            .bold()
    );
    println!(
        "{}",
        "║  Store these in separate secure locations.                            ║"
            .white()
    );
    println!(
        "{}",
        "║  Any 3 shards can recover your identity if you lose this device.      ║"
            .white()
    );
    println!(
        "{}",
        "╠═══════════════════════════════════════════════════════════════════════╣"
            .red()
    );
    println!(
        "{}",
        "║                                                                       ║"
            .red()
    );

    // Display each shard
    println!(
        "{}  {}",
        "║".red(),
        format!("Shard A: {}", shards[0].to_hex()).bright_white()
    );
    println!(
        "{}",
        "║                                                                       ║"
            .red()
    );
    println!(
        "{}  {}",
        "║".red(),
        format!("Shard B: {}", shards[1].to_hex()).bright_white()
    );
    println!(
        "{}",
        "║                                                                       ║"
            .red()
    );
    println!(
        "{}  {}",
        "║".red(),
        format!("Shard C: {}", shards[2].to_hex()).bright_white()
    );
    println!(
        "{}",
        "║                                                                       ║"
            .red()
    );
    println!(
        "{}",
        "╠═══════════════════════════════════════════════════════════════════════╣"
            .red()
    );
    println!(
        "{}",
        "║  WARNING: These Neural Shards will NOT be shown again!                ║"
            .red()
            .bold()
    );
    println!(
        "{}",
        "║  WARNING: If you lose all 3 shards AND this device, recovery is       ║"
            .red()
            .bold()
    );
    println!(
        "{}",
        "║           IMPOSSIBLE.                                                 ║"
            .red()
            .bold()
    );
    println!(
        "{}",
        "╚═══════════════════════════════════════════════════════════════════════╝"
            .red()
            .bold()
    );

    // Wait for user acknowledgment
    println!();
    print!(
        "{}",
        "Press Enter when you have saved your Neural Shards...".yellow()
    );
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(())
}

pub async fn login_email(
    server: &str,
    email: &str,
    password: &str,
    machine_id: Option<Uuid>,
) -> Result<()> {
    println!("{}", "=== Email Authentication ===".bold().cyan());

    print_email_login_info(email, machine_id.as_ref());
    let login_result = attempt_email_login(server, email, password, machine_id).await?;

    print_email_login_success(&login_result);
    save_session_data(&login_result)?;
    Ok(())
}

fn print_credentials_info(identity_id: &Uuid, machine_id: &Uuid) {
    println!("\n{}", "Step 1: Loading credentials...".yellow());
    println!("  Identity ID: {}", identity_id);
    println!("  Machine ID: {}", machine_id);
}

async fn request_challenge(server: &str, machine_id: &Uuid) -> Result<ChallengeResponse> {
    println!(
        "\n{}",
        "Step 2: Requesting authentication challenge...".yellow()
    );

    let client = reqwest::Client::new();
    let challenge_url = format!("{}/v1/auth/challenge?machine_id={}", server, machine_id);
    let response = client
        .get(&challenge_url)
        .send()
        .await
        .context("Failed to get challenge")?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        anyhow::bail!("Server returned error {}: {}", status, error_text);
    }

    let challenge_data: ChallengeResponse = response.json().await?;
    println!("  Challenge ID: {}", challenge_data.challenge_id);
    println!("  Expires At: {}", challenge_data.expires_at);
    Ok(challenge_data)
}

fn sign_challenge(
    challenge_data: &ChallengeResponse,
    credentials: &ClientCredentials,
    neural_key: &NeuralKey,
) -> Result<Vec<u8>> {
    println!("\n{}", "Step 4: Signing challenge...".yellow());

    let challenge_bytes = base64::engine::general_purpose::STANDARD
        .decode(&challenge_data.challenge)
        .context("Failed to decode challenge")?;

    let challenge: zero_auth_crypto::Challenge =
        serde_json::from_slice(&challenge_bytes).context("Failed to deserialize challenge")?;

    let canonical_challenge = zero_auth_crypto::canonicalize_challenge(&challenge);

    let machine_keypair = derive_machine_keypair(
        neural_key,
        &credentials.identity_id,
        &credentials.machine_id,
        0,
        MachineKeyCapabilities::AUTHENTICATE
            | MachineKeyCapabilities::SIGN
            | MachineKeyCapabilities::ENCRYPT,
    )?;

    let signature = sign_message(machine_keypair.signing_key_pair(), &canonical_challenge);
    println!("{}", "✓ Challenge signed".green());
    Ok(signature.to_vec())
}

async fn submit_login(
    server: &str,
    challenge_id: &Uuid,
    machine_id: &Uuid,
    signature: &[u8],
) -> Result<LoginResponse> {
    println!("\n{}", "Step 5: Submitting login request...".yellow());

    let login_request = serde_json::json!({
        "challenge_id": challenge_id,
        "machine_id": machine_id,
        "signature": hex::encode(signature)
    });

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/v1/auth/login/machine", server))
        .json(&login_request)
        .send()
        .await
        .context("Failed to login")?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        anyhow::bail!("Login failed {}: {}", status, error_text);
    }

    Ok(response.json().await?)
}

fn print_login_success(login_result: &LoginResponse) {
    println!("{}", "✓ Login successful!".green().bold());
    println!("\n{}", "Session Details:".bold());
    println!("  Session ID: {}", login_result.session_id);
    println!("  Expires At: {}", login_result.expires_at);
    println!(
        "\n  Access Token: {}",
        &login_result.access_token[..50].dimmed()
    );
    println!("  {}...", "...".dimmed());
}

fn print_email_login_info(email: &str, machine_id: Option<&Uuid>) {
    println!("\n{}", "Step 1: Validating credentials...".yellow());
    println!("  Email: {}", email);
    if let Some(mid) = machine_id {
        println!("  Machine ID: {}", mid);
    }
}

async fn attempt_email_login(
    server: &str,
    email: &str,
    password: &str,
    machine_id: Option<Uuid>,
) -> Result<LoginResponse> {
    println!("\n{}", "Step 2: Authenticating with email...".yellow());

    let client = reqwest::Client::new();
    let request = serde_json::json!({
        "email": email,
        "password": password,
        "machine_id": machine_id,
        "mfa_code": null
    });

    let response = client
        .post(format!("{}/v1/auth/login/email", server))
        .json(&request)
        .send()
        .await
        .context("Failed to send login request")?;

    if !response.status().is_success() {
        return handle_email_login_error(response, email).await;
    }

    Ok(response.json().await?)
}

async fn handle_email_login_error<T>(response: reqwest::Response, email: &str) -> Result<T> {
    let status = response.status();
    let error_text = response.text().await?;

    if error_text.contains("Machine ID required") || error_text.contains("Available machines") {
        println!("\n{}", "❌ Machine ID required".red().bold());
        println!("\n{}", error_text.yellow());
        print_machine_id_help(email);
        anyhow::bail!("Please provide a machine_id to continue");
    }

    anyhow::bail!("Login failed {}: {}", status, error_text)
}

fn print_machine_id_help(email: &str) {
    println!("\n{}", "💡 Available options:".bold());
    println!("  1. List your machines: cargo run -p client -- list-machines");
    println!("  2. Login with specific machine: cargo run -p client -- login-email -e {} -p <password> -m <machine-id>", email);
    println!("  3. Or use machine key login: cargo run -p client -- login");
}

fn print_email_login_success(login_result: &LoginResponse) {
    if let Some(warning) = &login_result.warning {
        println!("\n{}", format!("⚠ Warning: {}", warning).yellow());
    }

    println!("{}", "✓ Login successful!".green().bold());
    println!("\n{}", "Session Details:".bold());
    println!("  Session ID: {}", login_result.session_id);
    println!("  Machine ID: {}", login_result.machine_id);
    println!("  Expires At: {}", login_result.expires_at);
    println!(
        "\n  Access Token: {}",
        &login_result.access_token[..50].dimmed()
    );
    println!("  {}...", "...".dimmed());

    if login_result.warning.is_some() {
        println!(
            "\n{}",
            "💡 Tip: This session is using a virtual machine. For better security, enroll a real device.".dimmed()
        );
    }
}

fn save_session_data(login_result: &LoginResponse) -> Result<()> {
    let session = SessionData {
        access_token: login_result.access_token.clone(),
        refresh_token: login_result.refresh_token.clone(),
        session_id: login_result.session_id,
        expires_at: login_result.expires_at.clone(),
    };

    save_session(&session)?;
    println!("\n{}", "✓ Session saved to ./.session/session.json".green());
    println!(
        "\n{}",
        "You can now use the access token to make authenticated requests!".green()
    );
    Ok(())
}
