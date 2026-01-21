/*!
 * Machine management commands
 */

use anyhow::{Context, Result};
use colored::*;
use uuid::Uuid;
use zero_auth_crypto::{
    canonicalize_enrollment_message, derive_identity_signing_keypair, derive_machine_keypair,
    sign_message, MachineKeyCapabilities, NeuralKey,
};

use crate::storage::{
    load_and_reconstruct_neural_key, load_credentials, load_session, prompt_neural_shard,
    prompt_passphrase,
};
use crate::types::{EnrollMachineResponse, ListMachinesResponse};

pub async fn enroll_machine(server: &str, device_name: &str, device_platform: &str) -> Result<()> {
    println!("{}", "=== Enrolling New Machine ===".bold().cyan());

    let credentials = load_credentials()?;
    let session = load_session()?;

    let new_machine_id = generate_machine_id();

    // Prompt for passphrase and user shard to reconstruct Neural Key
    println!(
        "\n{}",
        "Step 2: Reconstructing Neural Key from shards...".yellow()
    );
    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let user_shard = prompt_neural_shard()?;
    let (neural_key, _) = load_and_reconstruct_neural_key(&passphrase, &user_shard)?;
    println!("{}", "✓ Neural Key reconstructed in memory".green());

    let new_keypair =
        derive_new_machine_keypair(&neural_key, &credentials.identity_id, &new_machine_id)?;
    let auth_signature = create_enrollment_signature(
        &neural_key,
        &credentials.identity_id,
        &new_machine_id,
        &new_keypair,
    )?;

    let response = send_enrollment_request(
        server,
        &session.access_token,
        &new_machine_id,
        &credentials.identity_id,
        &new_keypair,
        &auth_signature,
        device_name,
        device_platform,
    )
    .await?;

    print_enrollment_success(&response, device_name, device_platform);
    Ok(())
}

pub async fn list_machines(server: &str) -> Result<()> {
    println!("{}", "=== Enrolled Machines ===".bold().cyan());

    let session = load_session()?;
    let credentials = load_credentials()?;

    let machines = fetch_machines(server, &session.access_token, &credentials.identity_id).await?;
    print_machines_list(&machines);

    Ok(())
}

pub async fn revoke_machine(server: &str, machine_id_str: &str, reason: &str) -> Result<()> {
    println!("{}", "=== Revoking Machine ===".bold().cyan());

    let session = load_session()?;
    let machine_id = parse_machine_id(machine_id_str)?;

    send_revocation_request(server, &session.access_token, &machine_id, reason).await?;
    print_revocation_success(&machine_id);

    Ok(())
}

fn generate_machine_id() -> Uuid {
    let new_machine_id = Uuid::new_v4();
    println!("\n{}", "Step 1: Generating new machine ID...".yellow());
    println!("  New Machine ID: {}", new_machine_id);
    new_machine_id
}

fn derive_new_machine_keypair(
    neural_key: &NeuralKey,
    identity_id: &Uuid,
    machine_id: &Uuid,
) -> Result<zero_auth_crypto::MachineKeyPair> {
    println!("\n{}", "Step 3: Deriving new machine keys...".yellow());

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
        "  Signing Public Key: {}",
        hex::encode(keypair.signing_public_key())
    );
    println!(
        "  Encryption Public Key: {}",
        hex::encode(keypair.encryption_public_key())
    );
    Ok(keypair)
}

fn create_enrollment_signature(
    neural_key: &NeuralKey,
    identity_id: &Uuid,
    machine_id: &Uuid,
    keypair: &zero_auth_crypto::MachineKeyPair,
) -> Result<Vec<u8>> {
    println!(
        "\n{}",
        "Step 4: Creating authorization signature...".yellow()
    );

    let (_, identity_signing_keypair) = derive_identity_signing_keypair(neural_key, identity_id)?;
    let created_at = chrono::Utc::now().timestamp() as u64;
    let namespace_id = identity_id;

    let message = canonicalize_enrollment_message(
        machine_id,
        namespace_id,
        &keypair.signing_public_key(),
        &keypair.encryption_public_key(),
        (MachineKeyCapabilities::AUTHENTICATE
            | MachineKeyCapabilities::SIGN
            | MachineKeyCapabilities::ENCRYPT)
            .bits(),
        created_at,
    );

    let signature = sign_message(&identity_signing_keypair, &message);
    println!("{}", "✓ Authorization signature created".green());
    Ok(signature.to_vec())
}

#[allow(clippy::too_many_arguments)]
async fn send_enrollment_request(
    server: &str,
    access_token: &str,
    machine_id: &Uuid,
    namespace_id: &Uuid,
    keypair: &zero_auth_crypto::MachineKeyPair,
    auth_signature: &[u8],
    device_name: &str,
    device_platform: &str,
) -> Result<EnrollMachineResponse> {
    println!("\n{}", "Step 5: Sending enrollment request...".yellow());

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/v1/machines/enroll", server))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&serde_json::json!({
            "machine_id": machine_id,
            "namespace_id": namespace_id,
            "signing_public_key": hex::encode(keypair.signing_public_key()),
            "encryption_public_key": hex::encode(keypair.encryption_public_key()),
            "capabilities": ["AUTHENTICATE", "SIGN", "ENCRYPT"],
            "device_name": device_name,
            "device_platform": device_platform,
            "authorization_signature": hex::encode(auth_signature)
        }))
        .send()
        .await
        .context("Failed to send enrollment request")?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        anyhow::bail!("Enrollment failed {}: {}", status, error_text);
    }

    Ok(response.json().await?)
}

fn print_enrollment_success(
    response: &EnrollMachineResponse,
    device_name: &str,
    device_platform: &str,
) {
    println!("{}", "✓ Machine enrolled successfully!".green().bold());
    println!("\n{}", "Enrollment Details:".bold());
    println!("  Machine ID: {}", response.machine_id);
    println!("  Namespace ID: {}", response.namespace_id);
    println!("  Enrolled At: {}", response.enrolled_at);
    println!("  Device Name: {}", device_name);
    println!("  Device Platform: {}", device_platform);
    println!(
        "\n{}",
        "This device can now authenticate to your identity!".green()
    );
}

async fn fetch_machines(
    server: &str,
    access_token: &str,
    namespace_id: &Uuid,
) -> Result<ListMachinesResponse> {
    println!("\n{}", "Fetching machines...".yellow());

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{}/v1/machines?namespace_id={}",
            server, namespace_id
        ))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .context("Failed to fetch machines")?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        anyhow::bail!("Failed to list machines {}: {}", status, error_text);
    }

    Ok(response.json().await?)
}

fn print_machines_list(list_response: &ListMachinesResponse) {
    println!(
        "{}",
        format!("✓ Found {} machines", list_response.machines.len()).green()
    );
    println!();

    for (i, machine) in list_response.machines.iter().enumerate() {
        println!("{}", format!("Machine #{}", i + 1).bold());
        println!("  ID: {}", machine.machine_id);
        println!(
            "  Device: {} ({})",
            machine.device_name, machine.device_platform
        );
        println!("  Created: {}", machine.created_at);
        if let Some(last_used) = &machine.last_used_at {
            println!("  Last Used: {}", last_used);
        }
        if machine.revoked {
            println!("  Status: {}", "REVOKED".red().bold());
        } else {
            println!("  Status: {}", "ACTIVE".green().bold());
        }
        println!();
    }
}

fn parse_machine_id(machine_id_str: &str) -> Result<Uuid> {
    Uuid::parse_str(machine_id_str).context("Invalid machine ID format. Expected UUID.")
}

async fn send_revocation_request(
    server: &str,
    access_token: &str,
    machine_id: &Uuid,
    reason: &str,
) -> Result<()> {
    println!("\n{}", "Sending revocation request...".yellow());
    println!("  Machine ID: {}", machine_id);
    println!("  Reason: {}", reason);

    let client = reqwest::Client::new();
    let response = client
        .delete(format!("{}/v1/machines/{}", server, machine_id))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&serde_json::json!({
            "reason": reason
        }))
        .send()
        .await
        .context("Failed to send revocation request")?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        anyhow::bail!("Revocation failed {}: {}", status, error_text);
    }

    Ok(())
}

fn print_revocation_success(machine_id: &Uuid) {
    println!("{}", "✓ Machine revoked successfully!".green().bold());
    println!("\n{}", "Effects:".bold());
    println!("  • Machine marked as revoked");
    println!("  • All active sessions terminated");
    println!("  • Machine cannot authenticate anymore");
    println!("  • Event published to integrations");
    println!(
        "\n{}",
        format!("Machine {} has been permanently revoked.", machine_id).dimmed()
    );
}
