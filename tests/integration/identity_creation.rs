use serde_json::json;
use uuid::Uuid;
use zero_auth_crypto::{
    canonicalize_identity_creation_message, derive_identity_signing_keypair, derive_machine_keypair,
    sign_message, MachineKeyCapabilities, NeuralKey,
};

#[path = "../common/mod.rs"]
mod common;
use common::server::{send_request, setup_test_environment, TestServer};

#[tokio::test]
#[ignore] // Run with: cargo test --test identity_creation -- --ignored
async fn test_identity_creation_flow() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Zero-Auth Identity Creation Integration Test ===\n");

    // Setup test environment
    setup_test_environment()?;
    println!("✓ Test environment configured");

    // 1. Generate a Neural Key
    let neural_key = NeuralKey::generate()?;
    println!("✓ Generated Neural Key");

    // 2. Generate UUIDs
    let identity_id = Uuid::new_v4();
    let machine_id = Uuid::new_v4();

    println!("✓ Generated IDs");
    println!("  Identity ID: {}", identity_id);
    println!("  Machine ID: {}\n", machine_id);

    // 3. Derive the identity signing key from the neural key
    let (identity_signing_public_key, identity_signing_keypair) =
        derive_identity_signing_keypair(&neural_key, &identity_id)?;

    println!("✓ Derived Identity Signing Public Key");
    println!(
        "  Identity Signing Public Key: {}\n",
        hex::encode(identity_signing_public_key)
    );

    // 4. Derive machine key pair from the neural key
    let machine_keypair = derive_machine_keypair(
        &neural_key,
        &identity_id,
        &machine_id,
        0, // epoch 0 for initial machine key
        MachineKeyCapabilities::AUTHENTICATE
            | MachineKeyCapabilities::SIGN
            | MachineKeyCapabilities::ENCRYPT,
    )?;

    let machine_signing_pk = machine_keypair.signing_public_key();
    let machine_encryption_pk = machine_keypair.encryption_public_key();

    println!("✓ Derived Machine Key");
    println!("  Signing Public Key: {}", hex::encode(machine_signing_pk));
    println!(
        "  Encryption Public Key: {}\n",
        hex::encode(machine_encryption_pk)
    );

    // 5. Create the canonical authorization message
    let created_at = chrono::Utc::now().timestamp() as u64;
    let message = canonicalize_identity_creation_message(
        &identity_id,
        &identity_signing_public_key,
        &machine_id,
        &machine_signing_pk,
        &machine_encryption_pk,
        created_at,
    );

    // 6. Sign the message with the identity signing key
    let signature = sign_message(&identity_signing_keypair, &message);

    println!("✓ Created Authorization Signature");
    println!("  Message length: {} bytes", message.len());
    println!("  Signature: {}\n", hex::encode(signature));

    // 7. Build the JSON request
    let request = json!({
        "identity_id": identity_id,
        "identity_signing_public_key": hex::encode(identity_signing_public_key),
        "authorization_signature": hex::encode(signature),
        "machine_key": {
            "machine_id": machine_id,
            "signing_public_key": hex::encode(machine_signing_pk),
            "encryption_public_key": hex::encode(machine_encryption_pk),
            "capabilities": ["AUTHENTICATE", "SIGN", "ENCRYPT"],
            "device_name": "Integration Test Device",
            "device_platform": "TEST"
        },
        "namespace_name": "Personal",
        "created_at": created_at
    });

    println!("=== Complete Request JSON ===");
    println!("{}\n", serde_json::to_string_pretty(&request)?);

    // 8. Start the server
    println!("=== Starting Server ===");
    let server = TestServer::start()?;

    // Wait for server to be ready
    println!("Waiting for server to start...");
    server.wait_for_ready().await?;
    println!("✓ Server is ready\n");

    // 9. Send the request
    println!("=== Sending Request to Server ===");
    let response = send_request(reqwest::Method::POST, "/v1/identity", Some(&request)).await?;

    println!("✓ Success! Response:");
    println!("{}\n", serde_json::to_string_pretty(&response)?);

    // 10. Verify response structure
    assert!(
        response.get("identity_id").is_some(),
        "Response should contain identity_id"
    );
    assert!(
        response.get("identity_signing_public_key").is_some(),
        "Response should contain identity_signing_public_key"
    );

    // Shutdown server
    println!("=== Shutting Down Server ===");
    server.stop()?;
    println!("✓ Server stopped");
    println!("\n=== Test Passed ===");

    Ok(())
}
