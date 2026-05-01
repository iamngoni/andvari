//! Postgres dynamic-secrets engine.
//!
//! Configured via `ANDVARI_PG_DYNAMIC_URL` — the admin connection string the
//! engine uses to `CREATE ROLE` / `DROP ROLE`. Operators with stricter
//! requirements should plug in a per-workspace engine config when the
//! engine-config slice lands.
//!
//! Lease shape:
//! - `scope` = the database name to grant access to. Empty / `"*"` means all.
//! - `params.privileges` = one of `"readonly"` (SELECT only), `"readwrite"`
//!   (CRUD on tables), or `"all"`. Defaults to `"readonly"`.
//!
//! Issued credentials:
//! - `username` = `andv_lease_<short uuid>`
//! - `password` = 24 random base64url chars
//! - `dsn` = full connection string the caller can use immediately
//! - role created with `VALID UNTIL <expires_at>` so Postgres also enforces
//!   expiry server-side.

use std::time::Duration;

use andvari_core::dynamic::{DynamicEngine, DynamicError, IssuedLease, LeaseRequest};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresEngine {
    admin: PgPool,
    /// Host / port the leased credentials are usable from. Operators set
    /// `ANDVARI_PG_DYNAMIC_PUBLIC_URL` if it differs from the admin URL
    /// (e.g. admin uses an internal hostname, leases hand back the public one).
    public_dsn_template: String,
}

impl PostgresEngine {
    /// Build from `ANDVARI_PG_DYNAMIC_URL`. Returns `Ok(None)` if not configured.
    pub async fn from_env() -> Result<Option<Self>, DynamicError> {
        let admin_url = match std::env::var("ANDVARI_PG_DYNAMIC_URL") {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let public_dsn_template =
            std::env::var("ANDVARI_PG_DYNAMIC_PUBLIC_URL").unwrap_or_else(|_| admin_url.clone());

        let opts: PgConnectOptions = admin_url
            .parse()
            .map_err(|e: sqlx::Error| DynamicError::Engine(format!("bad pg url: {e}")))?;
        let admin = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(opts)
            .await
            .map_err(|e| DynamicError::Engine(format!("connect admin pg: {e}")))?;

        Ok(Some(Self {
            admin,
            public_dsn_template,
        }))
    }

    fn random_password() -> String {
        let mut buf = [0u8; 18];
        OsRng.fill_bytes(&mut buf);
        URL_SAFE_NO_PAD.encode(buf)
    }

    fn role_name(lease_id: Uuid) -> String {
        // Use the first 8 hex chars of the UUID — enough uniqueness for a
        // role name without making it ugly. Postgres truncates at 63.
        let hex: String = lease_id.simple().to_string();
        format!("andv_lease_{}", &hex[..16])
    }

    fn rewrite_dsn_user_pass(template: &str, user: &str, pass: &str) -> String {
        // Replace the userinfo portion of the DSN with the new role's
        // credentials. We assume the template starts with
        // `postgres://something@host…` — split on `://` and `@`, rebuild.
        let (scheme, rest) = match template.split_once("://") {
            Some(s) => s,
            None => return template.to_string(),
        };
        let host_and_path = rest.rsplit_once('@').map(|(_, h)| h).unwrap_or(rest);
        format!("{scheme}://{user}:{pass}@{host_and_path}")
    }
}

#[async_trait]
impl DynamicEngine for PostgresEngine {
    fn name(&self) -> &'static str {
        "postgres"
    }

    async fn issue_lease(&self, req: &LeaseRequest) -> Result<IssuedLease, DynamicError> {
        if req.ttl_seconds <= 0 {
            return Err(DynamicError::InvalidScope("ttl_seconds must be > 0".into()));
        }
        let lease_id = Uuid::new_v4();
        let role = Self::role_name(lease_id);
        let password = Self::random_password();
        let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(req.ttl_seconds);

        // Quote-validate the role name (we built it ourselves but be paranoid).
        if !role.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(DynamicError::Engine("role name validation failed".into()));
        }

        // Build the SQL with sanitized identifiers + parameterized password.
        // Note: PostgreSQL doesn't support binding identifiers, only values,
        // so the role name is interpolated. We've already validated it above.
        let valid_until = format_valid_until(expires_at);
        let create_sql = format!(
            "CREATE ROLE {role} LOGIN PASSWORD $1 VALID UNTIL '{valid_until}'"
        );
        sqlx::query(&create_sql)
            .bind(&password)
            .execute(&self.admin)
            .await
            .map_err(|e| DynamicError::Engine(format!("CREATE ROLE: {e}")))?;

        // Apply scope: privileges + database.
        let privileges = req
            .params
            .get("privileges")
            .and_then(|v| v.as_str())
            .unwrap_or("readonly");
        let database = if req.scope.is_empty() || req.scope == "*" {
            None
        } else {
            Some(req.scope.as_str())
        };

        if let Some(db) = database {
            if !is_valid_identifier(db) {
                let _ = self.revoke_lease(lease_id, "").await;
                return Err(DynamicError::InvalidScope(format!(
                    "database name '{db}' rejected"
                )));
            }
            let grant_db = format!("GRANT CONNECT ON DATABASE \"{db}\" TO {role}");
            sqlx::query(&grant_db)
                .execute(&self.admin)
                .await
                .map_err(|e| DynamicError::Engine(format!("GRANT CONNECT: {e}")))?;
        }

        match privileges {
            "readonly" => {
                let sql = format!(
                    "GRANT USAGE ON SCHEMA public TO {role}; \
                     GRANT SELECT ON ALL TABLES IN SCHEMA public TO {role}; \
                     ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO {role};"
                );
                sqlx::query(&sql)
                    .execute(&self.admin)
                    .await
                    .map_err(|e| DynamicError::Engine(format!("GRANT readonly: {e}")))?;
            }
            "readwrite" => {
                let sql = format!(
                    "GRANT USAGE ON SCHEMA public TO {role}; \
                     GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role}; \
                     ALTER DEFAULT PRIVILEGES IN SCHEMA public \
                       GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {role};"
                );
                sqlx::query(&sql)
                    .execute(&self.admin)
                    .await
                    .map_err(|e| DynamicError::Engine(format!("GRANT readwrite: {e}")))?;
            }
            "all" => {
                let sql = format!(
                    "GRANT USAGE ON SCHEMA public TO {role}; \
                     GRANT ALL ON ALL TABLES IN SCHEMA public TO {role}; \
                     GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO {role}; \
                     ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO {role};"
                );
                sqlx::query(&sql)
                    .execute(&self.admin)
                    .await
                    .map_err(|e| DynamicError::Engine(format!("GRANT all: {e}")))?;
            }
            other => {
                let _ = self.revoke_lease(lease_id, "").await;
                return Err(DynamicError::InvalidScope(format!(
                    "unknown privilege level '{other}' (use readonly|readwrite|all)"
                )));
            }
        }

        let dsn = Self::rewrite_dsn_user_pass(&self.public_dsn_template, &role, &password);

        Ok(IssuedLease {
            lease_id,
            engine: self.name().to_string(),
            credentials: serde_json::json!({
                "username": role,
                "password": password,
                "dsn": dsn,
                "privileges": privileges,
            }),
            expires_at,
        })
    }

    async fn revoke_lease(&self, lease_id: Uuid, _scope: &str) -> Result<(), DynamicError> {
        let role = Self::role_name(lease_id);
        if !role.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(DynamicError::Engine("role name validation failed".into()));
        }
        // Revoke privileges first so DROP ROLE doesn't complain about
        // dependent grants. Idempotent: ignore "role does not exist".
        let revoke = format!(
            "REASSIGN OWNED BY {role} TO CURRENT_USER; \
             DROP OWNED BY {role}; \
             DROP ROLE IF EXISTS {role};"
        );
        // Best-effort — if any of these fail we still try DROP ROLE.
        let _ = sqlx::query(&revoke).execute(&self.admin).await;
        let drop = format!("DROP ROLE IF EXISTS {role}");
        sqlx::query(&drop)
            .execute(&self.admin)
            .await
            .map_err(|e| DynamicError::Engine(format!("DROP ROLE: {e}")))?;
        Ok(())
    }
}

fn format_valid_until(t: OffsetDateTime) -> String {
    // Postgres accepts ISO 8601; format with explicit UTC offset.
    let format = time::macros::format_description!(
        "[year]-[month]-[day] [hour]:[minute]:[second]+00"
    );
    t.format(&format)
        .unwrap_or_else(|_| "infinity".to_string())
}

fn is_valid_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_name_is_deterministic_for_a_given_uuid() {
        let id = Uuid::nil();
        assert_eq!(PostgresEngine::role_name(id), "andv_lease_00000000000000000000000000000000"[..27].to_string());
    }

    #[test]
    fn dsn_rewrite_replaces_userinfo() {
        let out = PostgresEngine::rewrite_dsn_user_pass(
            "postgres://admin:adminpw@db.example.com:5432/app",
            "andv_lease_xyz",
            "tempPW",
        );
        assert_eq!(
            out,
            "postgres://andv_lease_xyz:tempPW@db.example.com:5432/app"
        );
    }

    #[test]
    fn dsn_rewrite_handles_no_userinfo() {
        let out = PostgresEngine::rewrite_dsn_user_pass(
            "postgres://db.example.com:5432/app",
            "u",
            "p",
        );
        assert_eq!(out, "postgres://u:p@db.example.com:5432/app");
    }

    #[test]
    fn identifier_validation() {
        assert!(is_valid_identifier("app"));
        assert!(is_valid_identifier("my_db_2026"));
        assert!(!is_valid_identifier(""));
        assert!(!is_valid_identifier("evil; DROP DATABASE app;"));
        assert!(!is_valid_identifier("with space"));
    }

    #[test]
    fn random_passwords_differ() {
        let a = PostgresEngine::random_password();
        let b = PostgresEngine::random_password();
        assert_ne!(a, b);
        assert!(a.len() >= 20);
    }
}
