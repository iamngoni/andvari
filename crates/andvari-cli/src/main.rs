use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "andvari", version, about = "Andvari secrets vault CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print the resolved configuration (placeholder until config slice lands)
    Config,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Config => {
            println!("(config resolution not yet implemented)");
        }
    }
    Ok(())
}
