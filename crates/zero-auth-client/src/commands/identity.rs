/*!
 * Identity creation command
 */

use anyhow::{Context, Result};
use colored::*;
use std::io::{self, Write};
use uuid::Uuid;
use zero_auth_crypto::{
    canonicalize_identity_creation_message, derive_identity_signing_keypair, derive_machine_keypair,
    sign_message, split_neural_key, verify_signature, Ed25519KeyPair, MachineKeyCapabilities,
    NeuralKey, NeuralShard,
};

use crate::storage::{prompt_new_passphrase, save_credentials_with_shards};
use crate::types::CreateIdentityResponse;

pub async fn create_identity(server: &str, device_name: &str, platform: &str) -> Result<()> {
    println!("{}", "=== Creating New Identity ===".bold().cyan());

    // Generate neural key and derive all keys first
    let neural_key = generate_neural_key()?;
    let (identity_id, machine_id) = generate_ids();
    let (identity_signing_public_key, identity_signing_keypair) =
        derive_identity_signing_keypair(&neural_key, &identity_id)?;

    let machine_keypair = create_machine_keypair(&neural_key, &identity_id, &machine_id)?;
    let signature = create_authorization_signature(
        &identity_id,
        &identity_signing_public_key,
        &machine_id,
        &machine_keypair.signing_public_key(),
        &machine_keypair.encryption_public_key(),
        &identity_signing_keypair,
    )?;

    // Send creation request to server
    let response = send_creation_request(
        server,
        &identity_id,
        &identity_signing_public_key,
        &machine_id,
        &machine_keypair,
        &signature,
        device_name,
        platform,
    )
    .await?;

    print_success(&response);

    // Now secure the Neural Key with Neural Shards
    println!(
        "\n{}",
        "Step 6: Securing your Neural Key with Neural Shards..."
            .yellow()
            .bold()
    );

    // Split neural key into 5 shards
    let shards = split_neural_key(&neural_key)
        .map_err(|e| anyhow::anyhow!("Failed to split Neural Key: {}", e))?;

    // Prompt for passphrase
    println!();
    let passphrase = prompt_new_passphrase()?;

    // Save 2 shards encrypted, get back 3 user shards
    let user_shards = save_credentials_with_shards(
        &shards,
        identity_id,
        machine_id,
        &hex::encode(identity_signing_public_key),
        &hex::encode(machine_keypair.signing_public_key()),
        &hex::encode(machine_keypair.encryption_public_key()),
        device_name,
        platform,
        &passphrase,
    )?;

    // Display user shards with warnings
    display_user_shards(&user_shards)?;

    // Final confirmation
    println!(
        "\n{}",
        "✓ Credentials saved (2 Neural Shards encrypted on device)".green()
    );
    println!(
        "{}",
        "✓ Your Neural Key was NEVER written to disk".green().bold()
    );

    Ok(())
}

fn generate_neural_key() -> Result<NeuralKey> {
    println!("\n{}", "Step 1: Generating Neural Key...".yellow());
    let neural_key = NeuralKey::generate()?;
    println!("{}", "✓ Neural Key generated (in memory only)".green());
    Ok(neural_key)
}

fn generate_ids() -> (Uuid, Uuid) {
    println!("\n{}", "Step 2: Generating IDs...".yellow());
    let identity_id = Uuid::new_v4();
    let machine_id = Uuid::new_v4();
    println!("  Identity ID: {}", identity_id);
    println!("  Machine ID: {}", machine_id);
    (identity_id, machine_id)
}

fn create_machine_keypair(
    neural_key: &NeuralKey,
    identity_id: &Uuid,
    machine_id: &Uuid,
) -> Result<zero_auth_crypto::MachineKeyPair> {
    println!("\n{}", "Step 3: Deriving machine keypair...".yellow());
    let keypair = derive_machine_keypair(
        neural_key,
        identity_id,
        machine_id,
        0,
        MachineKeyCapabilities::AUTHENTICATE
            | MachineKeyCapabilities::SIGN
            | MachineKeyCapabilities::ENCRYPT,
    )?;

    println!(
        "  Machine Signing Key: {}",
        hex::encode(keypair.signing_public_key())
    );
    println!(
        "  Machine Encryption Key: {}",
        hex::encode(keypair.encryption_public_key())
    );
    Ok(keypair)
}

fn create_authorization_signature(
    identity_id: &Uuid,
    identity_signing_public_key: &[u8],
    machine_id: &Uuid,
    machine_signing_pk: &[u8],
    machine_encryption_pk: &[u8],
    identity_signing_keypair: &Ed25519KeyPair,
) -> Result<Vec<u8>> {
    println!(
        "\n{}",
        "Step 4: Creating authorization signature...".yellow()
    );
    let created_at = chrono::Utc::now().timestamp() as u64;

    // Convert slices to fixed-size arrays
    let identity_signing_pk: [u8; 32] = identity_signing_public_key
        .try_into()
        .context("Invalid identity signing public key length")?;
    let machine_sign_pk: [u8; 32] = machine_signing_pk
        .try_into()
        .context("Invalid machine signing public key length")?;
    let machine_enc_pk: [u8; 32] = machine_encryption_pk
        .try_into()
        .context("Invalid machine encryption public key length")?;

    let message = canonicalize_identity_creation_message(
        identity_id,
        &identity_signing_pk,
        machine_id,
        &machine_sign_pk,
        &machine_enc_pk,
        created_at,
    );
    let signature = sign_message(identity_signing_keypair, &message);
    verify_signature(&identity_signing_pk, &message, &signature)?;
    println!("{}", "✓ Signature created and verified".green());
    Ok(signature.to_vec())
}

#[allow(clippy::too_many_arguments)]
async fn send_creation_request(
    server: &str,
    identity_id: &Uuid,
    identity_signing_public_key: &[u8],
    machine_id: &Uuid,
    machine_keypair: &zero_auth_crypto::MachineKeyPair,
    signature: &[u8],
    device_name: &str,
    platform: &str,
) -> Result<CreateIdentityResponse> {
    println!("\n{}", "Step 5: Sending creation request...".yellow());

    let created_at = chrono::Utc::now().timestamp() as u64;
    let request = build_creation_request(
        identity_id,
        identity_signing_public_key,
        machine_id,
        machine_keypair,
        signature,
        device_name,
        platform,
        created_at,
    );

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/v1/identity", server))
        .json(&request)
        .send()
        .await
        .context("Failed to send request to server")?;

    handle_response(response).await
}

#[allow(clippy::too_many_arguments)]
fn build_creation_request(
    identity_id: &Uuid,
    identity_signing_public_key: &[u8],
    machine_id: &Uuid,
    machine_keypair: &zero_auth_crypto::MachineKeyPair,
    signature: &[u8],
    device_name: &str,
    platform: &str,
    created_at: u64,
) -> serde_json::Value {
    serde_json::json!({
        "identity_id": identity_id,
        "identity_signing_public_key": hex::encode(identity_signing_public_key),
        "authorization_signature": hex::encode(signature),
        "machine_key": {
            "machine_id": machine_id,
            "signing_public_key": hex::encode(machine_keypair.signing_public_key()),
            "encryption_public_key": hex::encode(machine_keypair.encryption_public_key()),
            "capabilities": ["AUTHENTICATE", "SIGN", "ENCRYPT"],
            "device_name": device_name,
            "device_platform": platform
        },
        "namespace_name": "Personal",
        "created_at": created_at
    })
}

async fn handle_response(response: reqwest::Response) -> Result<CreateIdentityResponse> {
    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        anyhow::bail!("Server returned error {}: {}", status, error_text);
    }
    Ok(response.json().await?)
}

fn print_success(result: &CreateIdentityResponse) {
    println!("{}", "✓ Identity created successfully!".green().bold());
    println!("\n{}", "Server Response:".bold());
    println!("  Identity ID: {}", result.identity_id);
    println!("  Machine ID: {}", result.machine_id);
    println!("  Namespace ID: {}", result.namespace_id);
    println!("  Created At: {}", result.created_at);
}

fn display_user_shards(shards: &[NeuralShard; 3]) -> Result<()> {
    println!();
    println!(
        "{}",
        "╔═══════════════════════════════════════════════════════════════════════╗"
            .red()
            .bold()
    );
    println!(
        "{}",
        "║                       YOUR NEURAL SHARDS                              ║"
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
