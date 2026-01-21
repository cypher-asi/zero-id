# Integration Tests

This directory contains integration tests for the Zero-Auth system. These tests validate end-to-end workflows by running the actual server and making HTTP requests.

## Structure

```
tests/
├── common/              # Shared test utilities
│   ├── mod.rs
│   └── server.rs       # Server lifecycle management
└── integration/        # Integration test files
    └── identity_creation.rs
```

## Running Tests

### Run all integration tests

```bash
cargo test --workspace --test '*' -- --ignored
```

### Run a specific integration test

```bash
cargo test --test identity_creation -- --ignored
```

### Run with output

```bash
cargo test --test identity_creation -- --ignored --nocapture
```

## Writing New Tests

1. Create a new file in `tests/integration/` (e.g., `auth_flow.rs`)
2. Import common utilities:
   ```rust
   mod common;
   use common::server::{TestServer, setup_test_environment, send_request};
   ```
3. Write your test function:
   ```rust
   #[tokio::test]
   #[ignore]
   async fn test_your_flow() -> Result<(), Box<dyn std::error::Error>> {
       setup_test_environment()?;
       let server = TestServer::start()?;
       server.wait_for_ready().await?;
       
       // Your test logic here
       
       server.stop()?;
       Ok(())
   }
   ```
4. Add the test to `Cargo.toml`:
   ```toml
   [[test]]
   name = "your_test_name"
   path = "integration/your_test_file.rs"
   harness = true
   ```

## Test Utilities

### `TestServer`

Manages the server lifecycle:

```rust
let server = TestServer::start()?;     // Start server
server.wait_for_ready().await?;        // Wait until healthy
server.stop()?;                        // Stop server (automatic on drop)
```

### `send_request`

Make HTTP requests to the test server:

```rust
let response = send_request(
    reqwest::Method::POST,
    "/v1/identity",
    Some(&json_body),
).await?;
```

### `setup_test_environment`

Configure environment variables for testing:

```rust
setup_test_environment()?;
```

## Notes

- Tests are marked with `#[ignore]` to prevent them from running during regular `cargo test`
- Each test spawns its own server instance
- Tests use a test database at `./data/zero-auth-test.db`
- Server output is piped to prevent noise in test output
- Tests automatically clean up server processes on completion or panic
