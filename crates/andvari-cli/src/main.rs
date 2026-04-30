//! `andvari` CLI.

use std::io::Read;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};

mod api;
mod keyring_store;

use andvari_sdk::config::{Config, ResolveOptions};

use crate::api::ApiClient;

const KEYRING_SERVICE: &str = "andvari";

#[derive(Parser)]
#[command(name = "andvari", version, about = "Andvari secrets vault CLI")]
struct Cli {
    /// Override server URL
    #[arg(long, global = true)]
    server: Option<String>,
    /// Override workspace slug
    #[arg(long, short = 'w', global = true)]
    workspace: Option<String>,
    /// Override project slug
    #[arg(long, short = 'p', global = true)]
    project: Option<String>,
    /// Override environment name
    #[arg(long, short = 'e', global = true)]
    env: Option<String>,
    /// Override token (otherwise uses ANDVARI_TOKEN or OS keyring)
    #[arg(long, env = "ANDVARI_TOKEN", hide_env_values = true, global = true)]
    token: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print the resolved configuration.
    Config,
    /// Store a token in the OS keyring for the configured server URL.
    Login {
        /// Token to store. Reads from stdin if "-" or omitted.
        token: Option<String>,
    },
    /// Remove the stored token for the configured server URL.
    Logout,
    /// Get a secret value.
    Get { key: String },
    /// Set a secret value. Pass "-" to read the value from stdin.
    Set {
        key: String,
        /// Value, or "-" to read from stdin.
        value: String,
    },
    /// List secret keys in the configured env.
    Ls,
    /// Delete a secret.
    Rm { key: String },
    /// Show version history for a secret.
    History { key: String },
    /// Roll a secret back to a specific version id.
    Rollback { key: String, version_id: String },
    /// Run a command with all env secrets injected as env vars.
    Run {
        /// Command + args after `--`.
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let resolved = Config::resolve(ResolveOptions {
        start_dir: None,
        user_config_path: None,
        overrides: Config {
            server: cli.server.clone(),
            workspace: cli.workspace.clone(),
            project: cli.project.clone(),
            default_env: cli.env.clone(),
            ..Default::default()
        },
    })?;

    match cli.command {
        Commands::Config => {
            let json = serde_json::to_string_pretty(&resolved)?;
            println!("{json}");
        }
        Commands::Login { token } => login(&resolved, token)?,
        Commands::Logout => logout(&resolved)?,
        Commands::Get { key } => {
            let api = build_api(&resolved, &cli.token)?;
            let val = api.get_secret(&key).await?;
            println!("{val}");
        }
        Commands::Set { key, value } => {
            let api = build_api(&resolved, &cli.token)?;
            let value = if value == "-" { read_stdin()? } else { value };
            api.put_secret(&key, &value).await?;
            eprintln!("ok");
        }
        Commands::Ls => {
            let api = build_api(&resolved, &cli.token)?;
            let keys = api.list_secrets().await?;
            for k in keys {
                println!("{k}");
            }
        }
        Commands::Rm { key } => {
            let api = build_api(&resolved, &cli.token)?;
            api.delete_secret(&key).await?;
            eprintln!("deleted");
        }
        Commands::History { key } => {
            let api = build_api(&resolved, &cli.token)?;
            let versions = api.list_versions(&key).await?;
            let json = serde_json::to_string_pretty(&versions)?;
            println!("{json}");
        }
        Commands::Rollback { key, version_id } => {
            let api = build_api(&resolved, &cli.token)?;
            api.rollback(&key, &version_id).await?;
            eprintln!("rolled back");
        }
        Commands::Run { cmd } => {
            let api = build_api(&resolved, &cli.token)?;
            run_with_secrets(api, &cmd).await?;
        }
    }
    Ok(())
}

fn build_api(cfg: &Config, cli_token: &Option<String>) -> Result<ApiClient> {
    let server = cfg
        .server
        .clone()
        .context("no `server` configured (set in andvari.toml, ANDVARI_SERVER, or --server)")?;
    let workspace = cfg.workspace.clone().context("no `workspace` configured")?;
    let project = cfg.project.clone().context("no `project` configured")?;
    let env = cfg
        .default_env
        .clone()
        .context("no `default_env` configured")?;

    let token = match cli_token {
        Some(t) => t.clone(),
        None => keyring_store::load(KEYRING_SERVICE, &server)
            .context("no token: pass --token, set ANDVARI_TOKEN, or run `andvari login`")?,
    };

    Ok(ApiClient::new(server, token, workspace, project, env))
}

fn login(cfg: &Config, token: Option<String>) -> Result<()> {
    let server = cfg
        .server
        .clone()
        .context("set `server` in andvari.toml or pass --server")?;
    let token = match token {
        Some(t) if t == "-" => read_stdin()?,
        Some(t) => t,
        None => read_stdin()?,
    };
    keyring_store::store(KEYRING_SERVICE, &server, &token)?;
    eprintln!("token stored for {server}");
    Ok(())
}

fn logout(cfg: &Config) -> Result<()> {
    let server = cfg
        .server
        .clone()
        .context("set `server` in andvari.toml or pass --server")?;
    keyring_store::remove(KEYRING_SERVICE, &server)?;
    eprintln!("token removed for {server}");
    Ok(())
}

fn read_stdin() -> Result<String> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("read stdin")?;
    Ok(buf.trim_end_matches(['\n', '\r']).to_string())
}

async fn run_with_secrets(api: ApiClient, cmd: &[String]) -> Result<()> {
    let (program, args) = cmd
        .split_first()
        .ok_or_else(|| anyhow!("run requires a command after `--`"))?;

    let keys = api.list_secrets().await?;
    let mut child = std::process::Command::new(program);
    child.args(args);

    for key in keys {
        let value = api
            .get_secret(&key)
            .await
            .with_context(|| format!("fetching {key}"))?;
        child.env(&key, value);
    }

    let status = child.status().context("exec child")?;
    if !status.success() {
        bail!("child exited with {status}");
    }
    Ok(())
}
