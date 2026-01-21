/*!
 * Zero-Auth Client
 *
 * Official client for integrating applications with zero-auth:
 * 1. Create an identity with client-side cryptography
 * 2. Authenticate using machine key challenge-response
 * 3. Use JWT tokens to access protected resources
 * 4. Refresh tokens when they expire
 * 5. Validate tokens via introspection
 *
 * Usage:
 *   cargo run -p client -- create-identity
 *   cargo run -p client -- login
 *   cargo run -p client -- validate-token <token>
 *   cargo run -p client -- refresh-token
 */

mod commands;
mod storage;
mod types;

use anyhow::Result;
use clap::{Parser, Subcommand};
use uuid::Uuid;

// CLI structure
#[derive(Parser)]
#[command(name = "client")]
#[command(about = "Official client for zero-auth integration")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Zero-auth server URL
    #[arg(short, long, default_value = "http://127.0.0.1:8080")]
    server: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new identity on the zero-auth server
    CreateIdentity {
        /// Device name
        #[arg(short, long, default_value = "Example Client Device")]
        device_name: String,

        /// Device platform
        #[arg(short, long, default_value = "rust-app")]
        platform: String,
    },
    /// Login with machine key authentication
    Login,
    /// Add email credential to your identity
    AddEmail {
        /// Email address
        #[arg(short, long)]
        email: String,

        /// Password
        #[arg(short, long)]
        password: String,
    },
    /// Login with email and password
    LoginEmail {
        /// Email address
        #[arg(short, long)]
        email: String,

        /// Password
        #[arg(short, long)]
        password: String,

        /// Machine ID to use (optional - will list available machines if not provided)
        #[arg(short, long)]
        machine_id: Option<String>,
    },
    /// Validate a JWT token
    ValidateToken {
        /// JWT token to validate
        token: String,
    },
    /// Refresh the access token
    RefreshToken,
    /// Show stored credentials
    ShowCredentials,
    /// Test protected endpoint (simulates your app's protected API)
    TestProtected,
    /// Enroll a new machine (device)
    EnrollMachine {
        /// Device name
        #[arg(short, long, default_value = "New Device")]
        device_name: String,

        /// Device platform
        #[arg(short, long, default_value = "rust-app")]
        platform: String,
    },
    /// List all enrolled machines
    ListMachines,
    /// Revoke a machine
    RevokeMachine {
        /// Machine ID to revoke
        machine_id: String,

        /// Reason for revocation
        #[arg(short, long, default_value = "Manual revocation")]
        reason: String,
    },
    /// Recover identity from Neural Shards
    Recover {
        /// Neural Shards (hex encoded, need at least 3)
        #[arg(short = 'S', long, required = true, num_args = 3..=5)]
        shard: Vec<String>,

        /// Device name for the recovery machine
        #[arg(short, long, default_value = "Recovery Device")]
        device_name: String,

        /// Device platform
        #[arg(short, long, default_value = "rust-app")]
        platform: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::CreateIdentity {
            device_name,
            platform,
        } => commands::identity::create_identity(&cli.server, &device_name, &platform).await?,

        Commands::Login => commands::auth::login(&cli.server).await?,

        Commands::AddEmail { email, password } => {
            commands::credentials::add_email(&cli.server, &email, &password).await?
        }

        Commands::LoginEmail {
            email,
            password,
            machine_id,
        } => {
            let machine_uuid = machine_id
                .as_ref()
                .map(|s| Uuid::parse_str(s))
                .transpose()?;
            commands::auth::login_email(&cli.server, &email, &password, machine_uuid).await?
        }

        Commands::ValidateToken { token } => {
            commands::tokens::validate_token(&cli.server, &token).await?
        }

        Commands::RefreshToken => commands::tokens::refresh_token(&cli.server).await?,

        Commands::ShowCredentials => commands::show::show_credentials()?,

        Commands::TestProtected => commands::tokens::test_protected(&cli.server).await?,

        Commands::EnrollMachine {
            device_name,
            platform,
        } => commands::machines::enroll_machine(&cli.server, &device_name, &platform).await?,

        Commands::ListMachines => commands::machines::list_machines(&cli.server).await?,

        Commands::RevokeMachine { machine_id, reason } => {
            commands::machines::revoke_machine(&cli.server, &machine_id, &reason).await?
        }

        Commands::Recover {
            shard,
            device_name,
            platform,
        } => commands::recovery::recover(&cli.server, &shard, &device_name, &platform).await?,
    }

    Ok(())
}
