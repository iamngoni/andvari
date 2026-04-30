//! Postgres connection + migration helpers.

use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;
use thiserror::Error;
use tracing::info;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("ANDVARI_DATABASE_URL is not set")]
    MissingUrl,

    #[error("connect: {0}")]
    Connect(#[from] sqlx::Error),

    #[error("migrate: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

/// Connect to Postgres using `ANDVARI_DATABASE_URL`. Falls back to
/// `DATABASE_URL` if the namespaced var isn't set, matching what most local
/// tooling (psql, sqlx-cli) expects.
pub async fn connect() -> Result<PgPool, DbError> {
    let url = std::env::var("ANDVARI_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .map_err(|_| DbError::MissingUrl)?;

    let pool = PgPoolOptions::new()
        .max_connections(16)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&url)
        .await?;

    info!("connected to postgres");
    Ok(pool)
}

/// Apply embedded migrations. The migration files live in
/// `crates/andvari-server/migrations/` and are baked into the binary at
/// compile time.
pub async fn migrate(pool: &PgPool) -> Result<(), DbError> {
    sqlx::migrate!("./migrations").run(pool).await?;
    info!("migrations applied");
    Ok(())
}
