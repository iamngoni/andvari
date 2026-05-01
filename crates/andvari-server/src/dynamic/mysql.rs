//! MySQL dynamic-secrets engine.
//!
//! Configured via `ANDVARI_MYSQL_DYNAMIC_URL` (admin DSN, e.g.
//! `mysql://root:rootpw@db.host:3306/`). Per lease we issue a `CREATE USER`
//! / GRANT pair and DROP USER on revoke.

use std::time::Duration;

use andvari_core::dynamic::{DynamicEngine, DynamicError, IssuedLease, LeaseRequest};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;
use sqlx::mysql::{MySqlConnectOptions, MySqlPool, MySqlPoolOptions};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone)]
pub struct MySqlEngine {
    admin: MySqlPool,
    public_dsn_template: String,
}

impl MySqlEngine {
    pub async fn from_env() -> Result<Option<Self>, DynamicError> {
        let admin_url = match std::env::var("ANDVARI_MYSQL_DYNAMIC_URL") {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let public_dsn_template = std::env::var("ANDVARI_MYSQL_DYNAMIC_PUBLIC_URL")
            .unwrap_or_else(|_| admin_url.clone());

        let opts: MySqlConnectOptions = admin_url
            .parse()
            .map_err(|e: sqlx::Error| DynamicError::Engine(format!("bad mysql url: {e}")))?;
        let admin = MySqlPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(opts)
            .await
            .map_err(|e| DynamicError::Engine(format!("connect admin mysql: {e}")))?;

        Ok(Some(Self {
            admin,
            public_dsn_template,
        }))
    }

    fn user_name(lease_id: Uuid) -> String {
        let hex: String = lease_id.simple().to_string();
        // MySQL caps user names at 32 chars on 8+; stay well under.
        format!("andv_lease_{}", &hex[..16])
    }

    fn random_password() -> String {
        let mut buf = [0u8; 18];
        OsRng.fill_bytes(&mut buf);
        URL_SAFE_NO_PAD.encode(buf)
    }

    fn rewrite_dsn(template: &str, user: &str, pass: &str) -> String {
        let (scheme, rest) = match template.split_once("://") {
            Some(s) => s,
            None => return template.to_string(),
        };
        let host_and_path = rest.rsplit_once('@').map(|(_, h)| h).unwrap_or(rest);
        format!("{scheme}://{user}:{pass}@{host_and_path}")
    }
}

#[async_trait]
impl DynamicEngine for MySqlEngine {
    fn name(&self) -> &'static str {
        "mysql"
    }

    async fn issue_lease(&self, req: &LeaseRequest) -> Result<IssuedLease, DynamicError> {
        if req.ttl_seconds <= 0 {
            return Err(DynamicError::InvalidScope("ttl_seconds must be > 0".into()));
        }
        let lease_id = Uuid::new_v4();
        let user = Self::user_name(lease_id);
        let password = Self::random_password();
        let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(req.ttl_seconds);

        if !user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(DynamicError::Engine("user name validation failed".into()));
        }

        let create_sql = format!("CREATE USER '{user}'@'%' IDENTIFIED BY ?");
        sqlx::query(&create_sql)
            .bind(&password)
            .execute(&self.admin)
            .await
            .map_err(|e| DynamicError::Engine(format!("CREATE USER: {e}")))?;

        let privileges = req
            .params
            .get("privileges")
            .and_then(|v| v.as_str())
            .unwrap_or("readonly");
        let database = if req.scope.is_empty() || req.scope == "*" {
            "*".to_string()
        } else {
            if !req
                .scope
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                let _ = self.revoke_lease(lease_id, "").await;
                return Err(DynamicError::InvalidScope(format!(
                    "database '{}' rejected",
                    req.scope
                )));
            }
            format!("`{}`", req.scope)
        };

        let grant_priv = match privileges {
            "readonly" => "SELECT",
            "readwrite" => "SELECT, INSERT, UPDATE, DELETE",
            "all" => "ALL PRIVILEGES",
            other => {
                let _ = self.revoke_lease(lease_id, "").await;
                return Err(DynamicError::InvalidScope(format!(
                    "unknown privilege level '{other}' (use readonly|readwrite|all)"
                )));
            }
        };

        let grant_sql = format!("GRANT {grant_priv} ON {database}.* TO '{user}'@'%'");
        sqlx::query(&grant_sql)
            .execute(&self.admin)
            .await
            .map_err(|e| DynamicError::Engine(format!("GRANT: {e}")))?;
        sqlx::query("FLUSH PRIVILEGES")
            .execute(&self.admin)
            .await
            .map_err(|e| DynamicError::Engine(format!("FLUSH: {e}")))?;

        let dsn = Self::rewrite_dsn(&self.public_dsn_template, &user, &password);

        Ok(IssuedLease {
            lease_id,
            engine: self.name().to_string(),
            credentials: serde_json::json!({
                "username": user,
                "password": password,
                "dsn": dsn,
                "privileges": privileges,
            }),
            expires_at,
        })
    }

    async fn revoke_lease(&self, lease_id: Uuid, _scope: &str) -> Result<(), DynamicError> {
        let user = Self::user_name(lease_id);
        if !user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(DynamicError::Engine("user name validation failed".into()));
        }
        let drop = format!("DROP USER IF EXISTS '{user}'@'%'");
        sqlx::query(&drop)
            .execute(&self.admin)
            .await
            .map_err(|e| DynamicError::Engine(format!("DROP USER: {e}")))?;
        Ok(())
    }
}
