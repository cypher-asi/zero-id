/*!
 * Credential management commands
 */

use anyhow::{Context, Result};
use colored::*;

use crate::storage::{load_credentials, load_session};
use crate::types::AddCredentialResponse;

pub async fn add_email(server: &str, email: &str, password: &str) -> Result<()> {
    println!("{}", "=== Adding Email Credential ===".bold().cyan());

    let session = load_session()?;
    let credentials = load_credentials()?;

    validate_input(email, &credentials.identity_id)?;
    validate_password(password)?;

    let result = send_add_email_request(server, email, password, &session.access_token).await?;
    print_success(&result);

    Ok(())
}

fn validate_input(email: &str, identity_id: &uuid::Uuid) -> Result<()> {
    println!("\n{}", "Step 1: Validating input...".yellow());
    println!("  Email: {}", email);
    println!("  Identity ID: {}", identity_id);

    if !email.contains('@') || !email.contains('.') {
        anyhow::bail!("Invalid email format");
    }

    Ok(())
}

fn validate_password(password: &str) -> Result<()> {
    if password.len() < 12 {
        anyhow::bail!("Password must be at least 12 characters long");
    }
    if password.len() > 128 {
        anyhow::bail!("Password must be at most 128 characters long");
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        anyhow::bail!("Password must contain at least one uppercase letter");
    }
    if !password.chars().any(|c| c.is_lowercase()) {
        anyhow::bail!("Password must contain at least one lowercase letter");
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        anyhow::bail!("Password must contain at least one digit");
    }
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        anyhow::bail!("Password must contain at least one special character");
    }
    Ok(())
}

async fn send_add_email_request(
    server: &str,
    email: &str,
    password: &str,
    access_token: &str,
) -> Result<AddCredentialResponse> {
    println!("\n{}", "Step 2: Sending request to server...".yellow());

    let client = reqwest::Client::new();
    let request = serde_json::json!({
        "email": email,
        "password": password
    });

    let response = client
        .post(format!("{}/v1/credentials/email", server))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&request)
        .send()
        .await
        .context("Failed to send request")?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        anyhow::bail!("Server returned error {}: {}", status, error_text);
    }

    Ok(response.json().await?)
}

fn print_success(result: &AddCredentialResponse) {
    println!(
        "{}",
        "✓ Email credential added successfully!".green().bold()
    );
    println!("\n{}", result.message.green());
    println!(
        "\n{}",
        "You can now login with email and password using the 'login-email' command!".green()
    );
}
