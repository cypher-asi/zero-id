use std::process::{Child, Command};
use std::time::Duration;

/// Test master key used for integration tests
pub const TEST_MASTER_KEY: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Test database path
pub const TEST_DB_PATH: &str = "./data/zero-auth-test.db";

/// Server configuration for tests
pub struct TestServer {
    process: Child,
}

impl TestServer {
    /// Start the zero-auth-server with test configuration
    pub fn start() -> Result<Self, Box<dyn std::error::Error>> {
        // Create database directory
        std::fs::create_dir_all("./data")?;

        let process = Command::new("cargo")
            .args(["run", "--bin", "zero-auth-server"])
            .env("SERVICE_MASTER_KEY", TEST_MASTER_KEY)
            .env("DATABASE_PATH", TEST_DB_PATH)
            .env("JWT_ISSUER", "https://test.zero-auth.local")
            .env("JWT_AUDIENCE", "test-client")
            .env("RUST_LOG", "debug")
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()?;

        Ok(Self { process })
    }

    /// Wait for the server to be ready
    pub async fn wait_for_ready(&self) -> Result<(), Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let max_attempts = 30; // 30 seconds timeout

        for _ in 0..max_attempts {
            tokio::time::sleep(Duration::from_secs(1)).await;

            // Try to connect to the health endpoint
            if let Ok(response) = client.get("http://127.0.0.1:8080/health").send().await {
                if response.status().is_success() {
                    return Ok(());
                }
            }
        }

        Err("Server failed to start within 30 seconds".into())
    }

    /// Stop the server
    pub fn stop(mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.process.kill()?;
        Ok(())
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.process.kill();
    }
}

/// Setup test environment variables
pub fn setup_test_environment() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("SERVICE_MASTER_KEY", TEST_MASTER_KEY);
    std::env::set_var("DATABASE_PATH", TEST_DB_PATH);
    std::env::set_var("JWT_ISSUER", "https://test.zero-auth.local");
    std::env::set_var("JWT_AUDIENCE", "test-client");

    // Create database directory
    std::fs::create_dir_all("./data")?;

    Ok(())
}

/// Make an HTTP request to the server
pub async fn send_request(
    method: reqwest::Method,
    path: &str,
    body: Option<&serde_json::Value>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:8080{}", path);

    let mut request = client.request(method, &url);

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
