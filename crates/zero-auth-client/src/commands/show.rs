/*!
 * Show credentials command
 */

use anyhow::Result;
use colored::*;

use crate::storage::{load_credentials, load_session};

pub fn show_credentials() -> Result<()> {
    println!("{}", "=== Stored Credentials ===".bold().cyan());

    let credentials = load_credentials()?;
    print_credentials(&credentials);
    print_session_if_exists();

    Ok(())
}

fn print_credentials(credentials: &crate::types::ClientCredentials) {
    println!("\n{}", "Credentials:".bold());
    println!("  Identity ID: {}", credentials.identity_id);
    println!("  Machine ID: {}", credentials.machine_id);
    println!("  Device Name: {}", credentials.device_name);
    println!("  Device Platform: {}", credentials.device_platform);
    println!(
        "  Identity Signing Key: {}",
        credentials.identity_signing_public_key
    );
    println!(
        "  Machine Signing Key: {}",
        credentials.machine_signing_public_key
    );
    println!(
        "  Machine Encryption Key: {}",
        credentials.machine_encryption_public_key
    );
    println!(
        "  Neural Key Storage: {}",
        "2+1 Neural Shard Split (2 shards encrypted on device)".cyan()
    );
}

fn print_session_if_exists() {
    if let Ok(session) = load_session() {
        println!("\n{}", "Session:".bold());
        println!("  Session ID: {}", session.session_id);
        println!("  Expires At: {}", session.expires_at);
        println!(
            "  Access Token: {}...",
            &session.access_token[..30].dimmed()
        );
    } else {
        println!("\n{}", "No active session found".yellow());
    }
}
