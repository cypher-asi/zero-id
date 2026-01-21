/*!
 * Token management commands
 */

use anyhow::{Context, Result};
use colored::*;

use crate::storage::{load_credentials, load_session, save_session};
use crate::types::{IntrospectResponse, RefreshResponse, SessionData};

pub async fn validate_token(server: &str, token: &str) -> Result<()> {
    println!("{}", "=== Token Validation ===".bold().cyan());

    let result = introspect_token(server, token).await?;
    print_validation_result(&result);

    Ok(())
}

pub async fn refresh_token(server: &str) -> Result<()> {
    println!("{}", "=== Token Refresh ===".bold().cyan());

    let session = load_session()?;
    let credentials = load_credentials()?;

    let result = send_refresh_request(server, &session, &credentials.machine_id).await?;
    print_refresh_result(&result);
    update_session(&session, &result)?;

    Ok(())
}

pub async fn test_protected(server: &str) -> Result<()> {
    println!("{}", "=== Testing Protected Endpoint ===".bold().cyan());
    println!(
        "\n{}",
        "This simulates how YOUR application validates tokens.".dimmed()
    );

    let session = load_session()?;
    validate_and_demonstrate(server, &session.access_token).await?;

    Ok(())
}

async fn introspect_token(server: &str, token: &str) -> Result<IntrospectResponse> {
    println!(
        "\n{}",
        "Validating token via introspection endpoint...".yellow()
    );

    let client = reqwest::Client::new();
    let request = serde_json::json!({
        "token": token,
        "operation_type": "protected"
    });

    let response = client
        .post(format!("{}/v1/auth/introspect", server))
        .json(&request)
        .send()
        .await
        .context("Failed to validate token")?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        anyhow::bail!("Validation failed {}: {}", status, error_text);
    }

    Ok(response.json().await?)
}

fn print_validation_result(result: &IntrospectResponse) {
    if result.active {
        println!("{}", "✓ Token is VALID".green().bold());
        println!("\n{}", "Token Details:".bold());
        if let Some(identity_id) = result.identity_id {
            println!("  Identity ID: {}", identity_id);
        }
        if let Some(machine_id) = result.machine_id {
            println!("  Machine ID: {}", machine_id);
        }
        if let Some(mfa_verified) = result.mfa_verified {
            println!("  MFA Verified: {}", mfa_verified);
        }
        if let Some(capabilities) = &result.capabilities {
            println!("  Capabilities: {}", capabilities.join(", "));
        }
        if let Some(exp) = result.exp {
            println!(
                "  Expires: {}",
                chrono::DateTime::from_timestamp(exp, 0).unwrap()
            );
        }
    } else {
        println!("{}", "✗ Token is INVALID or EXPIRED".red().bold());
    }
}

async fn send_refresh_request(
    server: &str,
    session: &SessionData,
    machine_id: &uuid::Uuid,
) -> Result<RefreshResponse> {
    println!("\n{}", "Refreshing access token...".yellow());

    let client = reqwest::Client::new();
    let request = serde_json::json!({
        "refresh_token": session.refresh_token,
        "session_id": session.session_id,
        "machine_id": machine_id
    });

    let response = client
        .post(format!("{}/v1/auth/refresh", server))
        .json(&request)
        .send()
        .await
        .context("Failed to refresh token")?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        anyhow::bail!("Refresh failed {}: {}", status, error_text);
    }

    Ok(response.json().await?)
}

fn print_refresh_result(result: &RefreshResponse) {
    println!("{}", "✓ Token refreshed successfully!".green().bold());
    println!("\n{}", "New Token Details:".bold());
    println!("  Expires At: {}", result.expires_at);
    println!(
        "\n  New Access Token: {}",
        &result.access_token[..50].dimmed()
    );
    println!("  {}...", "...".dimmed());
}

fn update_session(old_session: &SessionData, result: &RefreshResponse) -> Result<()> {
    let updated_session = SessionData {
        access_token: result.access_token.clone(),
        refresh_token: result.refresh_token.clone(),
        session_id: old_session.session_id,
        expires_at: result.expires_at.clone(),
    };

    save_session(&updated_session)?;
    println!("\n{}", "✓ Updated session saved".green());
    Ok(())
}

async fn validate_and_demonstrate(server: &str, access_token: &str) -> Result<()> {
    println!(
        "\n{}",
        "Step 1: Validating token with zero-auth...".yellow()
    );

    let token_info = introspect_token(server, access_token).await?;

    if !token_info.active {
        anyhow::bail!("Token is not active");
    }

    println!("{}", "✓ Token is valid".green());
    print_demo_success(&token_info);

    Ok(())
}

fn print_demo_success(token_info: &IntrospectResponse) {
    println!("\n{}", "Step 2: Token validation successful!".yellow());
    println!("\n{}", "YOUR APP LOGIC:".bold().green());
    println!(
        "  ✓ User authenticated as Identity: {}",
        token_info.identity_id.unwrap()
    );
    println!("  ✓ Using Machine: {}", token_info.machine_id.unwrap());
    println!("  ✓ User has access to protected resources");
    println!(
        "\n{}",
        "This is where your app would process the request...".dimmed()
    );
}
