//! Namespace management integration tests.
//!
//! These tests verify the full namespace lifecycle including:
//! - Namespace creation
//! - Member management (add, update, remove)
//! - Role-based permissions
//! - Namespace deactivation and deletion

use serde_json::json;
use uuid::Uuid;
use zero_auth_crypto::{
    canonicalize_identity_creation_message, derive_identity_signing_keypair, derive_machine_keypair,
    sign_message, MachineKeyCapabilities, NeuralKey,
};

#[path = "../common/mod.rs"]
mod common;
use common::server::{send_request, setup_test_environment, TestServer};

/// Helper to create an identity and return (identity_id, access_token)
async fn create_identity_and_login() -> Result<(Uuid, String), Box<dyn std::error::Error>> {
    // 1. Generate a Neural Key
    let neural_key = NeuralKey::generate()?;

    // 2. Generate UUIDs
    let identity_id = Uuid::new_v4();
    let machine_id = Uuid::new_v4();

    // 3. Derive the identity signing key
    let (identity_signing_public_key, identity_signing_keypair) =
        derive_identity_signing_keypair(&neural_key, &identity_id)?;

    // 4. Derive machine key pair
    let machine_keypair = derive_machine_keypair(
        &neural_key,
        &identity_id,
        &machine_id,
        0,
        MachineKeyCapabilities::AUTHENTICATE
            | MachineKeyCapabilities::SIGN
            | MachineKeyCapabilities::ENCRYPT,
    )?;

    let machine_signing_pk = machine_keypair.signing_public_key();
    let machine_encryption_pk = machine_keypair.encryption_public_key();

    // 5. Create authorization message and sign
    let created_at = chrono::Utc::now().timestamp() as u64;
    let message = canonicalize_identity_creation_message(
        &identity_id,
        &identity_signing_public_key,
        &machine_id,
        &machine_signing_pk,
        &machine_encryption_pk,
        created_at,
    );

    let signature = sign_message(&identity_signing_keypair, &message);

    // 6. Create identity
    let request = json!({
        "identity_id": identity_id,
        "identity_signing_public_key": hex::encode(identity_signing_public_key),
        "authorization_signature": hex::encode(signature),
        "machine_key": {
            "machine_id": machine_id,
            "signing_public_key": hex::encode(machine_signing_pk),
            "encryption_public_key": hex::encode(machine_encryption_pk),
            "capabilities": ["AUTHENTICATE", "SIGN", "ENCRYPT"],
            "device_name": "Test Device",
            "device_platform": "TEST"
        },
        "namespace_name": "Personal",
        "created_at": created_at
    });

    let _response = send_request(reqwest::Method::POST, "/v1/identity", Some(&request)).await?;

    // 7. Get challenge for login
    let challenge_response = send_request(reqwest::Method::GET, "/v1/auth/challenge", None).await?;
    let challenge = challenge_response["challenge"].as_str().unwrap();

    // 8. Sign challenge
    let challenge_bytes = hex::decode(challenge)?;
    let challenge_signature = machine_keypair.sign(&challenge_bytes);

    // 9. Login
    let login_request = json!({
        "identity_id": identity_id,
        "machine_id": machine_id,
        "challenge": challenge,
        "signature": hex::encode(challenge_signature)
    });

    let login_response =
        send_request(reqwest::Method::POST, "/v1/auth/login/machine", Some(&login_request)).await?;

    let access_token = login_response["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    Ok((identity_id, access_token))
}

/// Helper to send authenticated request
async fn send_authenticated_request(
    method: reqwest::Method,
    path: &str,
    body: Option<&serde_json::Value>,
    token: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:9999{}", path);

    let mut request = client
        .request(method, &url)
        .header("Authorization", format!("Bearer {}", token));

    if let Some(json) = body {
        request = request.json(json);
    }

    let response = request.send().await?;
    let status = response.status();
    let body = response.json::<serde_json::Value>().await?;

    if !status.is_success() {
        return Err(format!("Server returned error {}: {}", status, body).into());
    }

    Ok(body)
}

#[tokio::test]
#[ignore] // Run with: cargo test --test namespace_management -- --ignored
async fn test_namespace_creation_flow() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Namespace Creation Flow Test ===\n");

    setup_test_environment()?;
    let server = TestServer::start()?;
    server.wait_for_ready().await?;
    println!("✓ Server is ready\n");

    // Create an identity
    let (identity_id, token) = create_identity_and_login().await?;
    println!("✓ Created identity: {}", identity_id);

    // Create a new namespace
    let namespace_id = Uuid::new_v4();
    let create_request = json!({
        "namespace_id": namespace_id,
        "name": "Test Namespace"
    });

    let response = send_authenticated_request(
        reqwest::Method::POST,
        "/v1/namespaces",
        Some(&create_request),
        &token,
    )
    .await?;

    println!("✓ Created namespace:");
    println!("{}\n", serde_json::to_string_pretty(&response)?);

    assert_eq!(response["namespace_id"].as_str().unwrap(), namespace_id.to_string());
    assert_eq!(response["name"].as_str().unwrap(), "Test Namespace");
    assert_eq!(response["owner_identity_id"].as_str().unwrap(), identity_id.to_string());
    assert!(response["active"].as_bool().unwrap());

    // Verify the namespace appears in list
    let list_response =
        send_authenticated_request(reqwest::Method::GET, "/v1/namespaces", None, &token).await?;

    let namespaces = list_response["namespaces"].as_array().unwrap();
    assert!(namespaces.len() >= 2); // Personal namespace + created namespace

    println!("✓ Namespace appears in list (total: {})", namespaces.len());

    server.stop()?;
    println!("\n=== Test Passed ===");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_add_and_remove_member_flow() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Add and Remove Member Flow Test ===\n");

    setup_test_environment()?;
    let server = TestServer::start()?;
    server.wait_for_ready().await?;

    // Create owner
    let (owner_id, owner_token) = create_identity_and_login().await?;
    println!("✓ Created owner: {}", owner_id);

    // Create member
    let (member_id, _member_token) = create_identity_and_login().await?;
    println!("✓ Created member: {}", member_id);

    // Create namespace
    let namespace_id = Uuid::new_v4();
    let create_request = json!({
        "namespace_id": namespace_id,
        "name": "Team Namespace"
    });

    send_authenticated_request(
        reqwest::Method::POST,
        "/v1/namespaces",
        Some(&create_request),
        &owner_token,
    )
    .await?;
    println!("✓ Created namespace: {}", namespace_id);

    // Add member
    let add_member_request = json!({
        "identity_id": member_id,
        "role": "member"
    });

    let add_response = send_authenticated_request(
        reqwest::Method::POST,
        &format!("/v1/namespaces/{}/members", namespace_id),
        Some(&add_member_request),
        &owner_token,
    )
    .await?;

    println!("✓ Added member:");
    println!("{}\n", serde_json::to_string_pretty(&add_response)?);

    assert_eq!(add_response["identity_id"].as_str().unwrap(), member_id.to_string());
    assert_eq!(add_response["role"].as_str().unwrap(), "member");

    // List members
    let members_response = send_authenticated_request(
        reqwest::Method::GET,
        &format!("/v1/namespaces/{}/members", namespace_id),
        None,
        &owner_token,
    )
    .await?;

    let members = members_response["members"].as_array().unwrap();
    assert_eq!(members.len(), 2); // Owner + member
    println!("✓ Listed members: {}", members.len());

    // Update member role to admin
    let update_request = json!({
        "role": "admin"
    });

    let update_response = send_authenticated_request(
        reqwest::Method::PATCH,
        &format!("/v1/namespaces/{}/members/{}", namespace_id, member_id),
        Some(&update_request),
        &owner_token,
    )
    .await?;

    assert_eq!(update_response["role"].as_str().unwrap(), "admin");
    println!("✓ Updated member role to admin");

    // Remove member
    let client = reqwest::Client::new();
    let url = format!(
        "http://127.0.0.1:9999/v1/namespaces/{}/members/{}",
        namespace_id, member_id
    );
    let response = client
        .delete(&url)
        .header("Authorization", format!("Bearer {}", owner_token))
        .send()
        .await?;

    assert!(response.status().is_success());
    println!("✓ Removed member");

    // Verify member is gone
    let members_response = send_authenticated_request(
        reqwest::Method::GET,
        &format!("/v1/namespaces/{}/members", namespace_id),
        None,
        &owner_token,
    )
    .await?;

    let members = members_response["members"].as_array().unwrap();
    assert_eq!(members.len(), 1); // Only owner
    println!("✓ Member removed from list");

    server.stop()?;
    println!("\n=== Test Passed ===");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_namespace_role_permissions() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Namespace Role Permissions Test ===\n");

    setup_test_environment()?;
    let server = TestServer::start()?;
    server.wait_for_ready().await?;

    // Create owner
    let (_owner_id, owner_token) = create_identity_and_login().await?;

    // Create member (will be regular member)
    let (member_id, member_token) = create_identity_and_login().await?;

    // Create potential new member
    let (new_member_id, _) = create_identity_and_login().await?;

    // Create namespace
    let namespace_id = Uuid::new_v4();
    let create_request = json!({
        "namespace_id": namespace_id,
        "name": "Permission Test NS"
    });

    send_authenticated_request(
        reqwest::Method::POST,
        "/v1/namespaces",
        Some(&create_request),
        &owner_token,
    )
    .await?;

    // Add member as regular member
    let add_member_request = json!({
        "identity_id": member_id,
        "role": "member"
    });

    send_authenticated_request(
        reqwest::Method::POST,
        &format!("/v1/namespaces/{}/members", namespace_id),
        Some(&add_member_request),
        &owner_token,
    )
    .await?;

    println!("✓ Setup complete");

    // Test: Regular member cannot add new members
    let add_attempt = json!({
        "identity_id": new_member_id,
        "role": "member"
    });

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:9999/v1/namespaces/{}/members", namespace_id);
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", member_token))
        .json(&add_attempt)
        .send()
        .await?;

    assert!(response.status().is_client_error());
    println!("✓ Regular member cannot add new members (permission denied)");

    // Test: Regular member cannot update namespace
    let update_ns = json!({ "name": "New Name" });
    let url = format!("http://127.0.0.1:9999/v1/namespaces/{}", namespace_id);
    let response = client
        .patch(&url)
        .header("Authorization", format!("Bearer {}", member_token))
        .json(&update_ns)
        .send()
        .await?;

    assert!(response.status().is_client_error());
    println!("✓ Regular member cannot update namespace (permission denied)");

    // Test: Owner can update namespace
    let update_response = send_authenticated_request(
        reqwest::Method::PATCH,
        &format!("/v1/namespaces/{}", namespace_id),
        Some(&update_ns),
        &owner_token,
    )
    .await?;

    assert_eq!(update_response["name"].as_str().unwrap(), "New Name");
    println!("✓ Owner can update namespace");

    server.stop()?;
    println!("\n=== Test Passed ===");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_namespace_deactivation_flow() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Namespace Deactivation Flow Test ===\n");

    setup_test_environment()?;
    let server = TestServer::start()?;
    server.wait_for_ready().await?;

    let (_owner_id, owner_token) = create_identity_and_login().await?;

    // Create namespace
    let namespace_id = Uuid::new_v4();
    let create_request = json!({
        "namespace_id": namespace_id,
        "name": "Deactivation Test NS"
    });

    send_authenticated_request(
        reqwest::Method::POST,
        "/v1/namespaces",
        Some(&create_request),
        &owner_token,
    )
    .await?;
    println!("✓ Created namespace");

    // Deactivate namespace
    let client = reqwest::Client::new();
    let url = format!(
        "http://127.0.0.1:9999/v1/namespaces/{}/deactivate",
        namespace_id
    );
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", owner_token))
        .send()
        .await?;

    assert!(response.status().is_success());
    println!("✓ Deactivated namespace");

    // Verify namespace is inactive
    let ns_response = send_authenticated_request(
        reqwest::Method::GET,
        &format!("/v1/namespaces/{}", namespace_id),
        None,
        &owner_token,
    )
    .await?;

    assert!(!ns_response["active"].as_bool().unwrap());
    println!("✓ Namespace is inactive");

    // Reactivate namespace
    let url = format!(
        "http://127.0.0.1:9999/v1/namespaces/{}/reactivate",
        namespace_id
    );
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", owner_token))
        .send()
        .await?;

    assert!(response.status().is_success());
    println!("✓ Reactivated namespace");

    // Verify namespace is active again
    let ns_response = send_authenticated_request(
        reqwest::Method::GET,
        &format!("/v1/namespaces/{}", namespace_id),
        None,
        &owner_token,
    )
    .await?;

    assert!(ns_response["active"].as_bool().unwrap());
    println!("✓ Namespace is active again");

    // Delete namespace (it has no other members)
    let url = format!("http://127.0.0.1:9999/v1/namespaces/{}", namespace_id);
    let response = client
        .delete(&url)
        .header("Authorization", format!("Bearer {}", owner_token))
        .send()
        .await?;

    assert!(response.status().is_success());
    println!("✓ Deleted namespace");

    server.stop()?;
    println!("\n=== Test Passed ===");
    Ok(())
}
