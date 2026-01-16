use zero_auth_crypto::{
    NeuralKey, MachineKeyCapabilities,
    derive_central_public_key, derive_machine_keypair,
    canonicalize_identity_creation_message, sign_message,
};
use uuid::Uuid;
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Zero-Auth Identity Creation Example ===\n");

    // 1. Generate a Neural Key (this would normally be done client-side)
    let neural_key = NeuralKey::generate()?;
    
    println!("✓ Generated Neural Key");

    // 2. Generate UUIDs
    let identity_id = Uuid::new_v4();
    let machine_id = Uuid::new_v4();
    
    println!("✓ Generated IDs");
    println!("  Identity ID: {}", identity_id);
    println!("  Machine ID: {}\n", machine_id);
    
    // 3. Derive the central signing key from the neural key
    let (central_public_key, central_signing_keypair) = derive_central_public_key(&neural_key, &identity_id)?;
    
    println!("✓ Derived Central Public Key");
    println!("  Central Public Key: {}\n", hex::encode(&central_public_key));
    
    // 4. Derive machine key pair from the neural key
    let machine_keypair = derive_machine_keypair(
        &neural_key,
        &identity_id,
        &machine_id,
        0, // epoch 0 for initial machine key
        MachineKeyCapabilities::AUTHENTICATE | MachineKeyCapabilities::SIGN | MachineKeyCapabilities::ENCRYPT,
    )?;
    
    let machine_signing_pk = machine_keypair.signing_public_key();
    let machine_encryption_pk = machine_keypair.encryption_public_key();
    
    println!("✓ Derived Machine Key");
    println!("  Signing Public Key: {}", hex::encode(&machine_signing_pk));
    println!("  Encryption Public Key: {}\n", hex::encode(&machine_encryption_pk));

    // 5. Create the canonical authorization message
    let created_at = chrono::Utc::now().timestamp() as u64;
    let message = canonicalize_identity_creation_message(
        &identity_id,
        &central_public_key,
        &machine_id,
        &machine_signing_pk,
        &machine_encryption_pk,
        created_at,
    );
    
    // 6. Sign the message with the central signing key
    let signature = sign_message(&central_signing_keypair, &message);
    
    println!("✓ Created Authorization Signature");
    println!("  Message length: {} bytes", message.len());
    println!("  Signature: {}\n", hex::encode(&signature));

    // 8. Build the JSON request
    let request = json!({
        "identity_id": identity_id,
        "central_public_key": hex::encode(&central_public_key),
        "authorization_signature": hex::encode(&signature),
        "machine_key": {
            "machine_id": machine_id,
            "signing_public_key": hex::encode(&machine_signing_pk),
            "encryption_public_key": hex::encode(&machine_encryption_pk),
            "capabilities": ["AUTHENTICATE", "SIGN", "ENCRYPT"],
            "device_name": "Example Device",
            "device_platform": "CLI"
        },
        "namespace_name": "Personal"
    });

    println!("=== Complete Request JSON ===");
    println!("{}\n", serde_json::to_string_pretty(&request)?);

    println!("=== PowerShell Command (copy and run in terminal 3) ===");
    let json_compact = serde_json::to_string(&request)?;
    let ps_safe = json_compact.replace("'", "''");  // Escape single quotes for PowerShell
    println!("$body = '{}'\nInvoke-RestMethod -Uri 'http://127.0.0.1:8080/v1/identity' -Method Post -Body $body -ContentType 'application/json'\n", ps_safe);

    Ok(())
}
