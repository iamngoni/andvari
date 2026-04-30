//! Thin HTTP wrapper used by the CLI subcommands.
//!
//! When the SDK slice (`#22`) lands, this gets replaced with the `Client`
//! type from `andvari-sdk` (which adds caching, retries, and logging
//! redaction). Until then, the CLI talks to the API directly.

use anyhow::{Context, Result, anyhow, bail};
use reqwest::Client;
use serde::Deserialize;

#[derive(Clone)]
pub struct ApiClient {
    server: String,
    token: String,
    workspace: String,
    project: String,
    env: String,
    http: Client,
}

#[derive(Deserialize)]
struct SecretValue {
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    value_b64: Option<String>,
}

#[derive(Deserialize)]
struct ListResp {
    secrets: Vec<SecretListItem>,
}

#[derive(Deserialize)]
struct SecretListItem {
    key: String,
}

impl ApiClient {
    pub fn new(server: String, token: String, workspace: String, project: String, env: String) -> Self {
        Self {
            server,
            token,
            workspace,
            project,
            env,
            http: Client::builder()
                .user_agent(concat!("andvari-cli/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("reqwest client"),
        }
    }

    fn url(&self, path: &str) -> String {
        let base = self.server.trim_end_matches('/');
        format!("{base}{path}")
    }

    fn auth(&self, b: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        b.bearer_auth(&self.token)
    }

    fn secret_path(&self, key: &str) -> String {
        format!(
            "/v1/ws/{}/projects/{}/envs/{}/secrets/{}",
            self.workspace, self.project, self.env, key
        )
    }

    pub async fn get_secret(&self, key: &str) -> Result<String> {
        let resp = self
            .auth(self.http.get(self.url(&self.secret_path(key))))
            .send()
            .await
            .context("network")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("HTTP {status}: {body}");
        }
        let body: SecretValue = resp.json().await.context("decode response")?;
        body.value
            .or(body.value_b64)
            .ok_or_else(|| anyhow!("response missing value/value_b64"))
    }

    pub async fn put_secret(&self, key: &str, value: &str) -> Result<()> {
        let resp = self
            .auth(
                self.http
                    .put(self.url(&self.secret_path(key)))
                    .json(&serde_json::json!({ "value": value })),
            )
            .send()
            .await
            .context("network")?;
        if !resp.status().is_success() {
            let s = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("HTTP {s}: {body}");
        }
        Ok(())
    }

    pub async fn delete_secret(&self, key: &str) -> Result<()> {
        let resp = self
            .auth(self.http.delete(self.url(&self.secret_path(key))))
            .send()
            .await
            .context("network")?;
        if !resp.status().is_success() {
            let s = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("HTTP {s}: {body}");
        }
        Ok(())
    }

    pub async fn list_secrets(&self) -> Result<Vec<String>> {
        let path = format!(
            "/v1/ws/{}/projects/{}/envs/{}/secrets",
            self.workspace, self.project, self.env
        );
        let resp = self
            .auth(self.http.get(self.url(&path)))
            .send()
            .await
            .context("network")?;
        if !resp.status().is_success() {
            let s = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("HTTP {s}: {body}");
        }
        let body: ListResp = resp.json().await.context("decode response")?;
        Ok(body.secrets.into_iter().map(|s| s.key).collect())
    }

    pub async fn list_versions(&self, key: &str) -> Result<serde_json::Value> {
        let path = format!("{}/versions", self.secret_path(key));
        let resp = self
            .auth(self.http.get(self.url(&path)))
            .send()
            .await
            .context("network")?;
        if !resp.status().is_success() {
            let s = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("HTTP {s}: {body}");
        }
        Ok(resp.json().await.context("decode response")?)
    }

    pub async fn rollback(&self, key: &str, version_id: &str) -> Result<()> {
        let path = format!("{}/rollback", self.secret_path(key));
        let resp = self
            .auth(
                self.http
                    .post(self.url(&path))
                    .json(&serde_json::json!({ "version_id": version_id })),
            )
            .send()
            .await
            .context("network")?;
        if !resp.status().is_success() {
            let s = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("HTTP {s}: {body}");
        }
        Ok(())
    }
}
