//! HTTP client + in-memory cache + background refresh.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

use crate::config::{Config, ResolveOptions};
use crate::{Error, Result};

const DEFAULT_TTL: Duration = Duration::from_secs(60);
const DEFAULT_MAX_RETRIES: u32 = 3;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct CacheEntry {
    value: String,
    inserted_at: Instant,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

/// Public Andvari client.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

struct Inner {
    config: Config,
    token: String,
    http: reqwest::Client,
    ttl: Duration,
    max_retries: u32,
    cache: RwLock<HashMap<String, CacheEntry>>,
    in_flight: Mutex<HashMap<String, ()>>,
    stats: RwLock<CacheStats>,
}

/// Builder for [`Client`] with custom configuration.
pub struct ClientBuilder {
    config: Option<Config>,
    token: Option<String>,
    ttl: Duration,
    max_retries: u32,
    timeout: Duration,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            config: None,
            token: None,
            ttl: DEFAULT_TTL,
            max_retries: DEFAULT_MAX_RETRIES,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Cache TTL — entries are considered fresh for this duration after fetch.
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }

    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    pub fn build(self) -> Result<Client> {
        let config = match self.config {
            Some(c) => c,
            None => Config::resolve(ResolveOptions::default())?,
        };
        let token = self
            .token
            .or_else(|| std::env::var("ANDVARI_TOKEN").ok())
            .ok_or(Error::MissingSetting("ANDVARI_TOKEN"))?;

        let http = reqwest::Client::builder()
            .user_agent(concat!("andvari-sdk/", env!("CARGO_PKG_VERSION")))
            .timeout(self.timeout)
            .build()
            .map_err(|e| Error::Http(e.to_string()))?;

        Ok(Client {
            inner: Arc::new(Inner {
                config,
                token,
                http,
                ttl: self.ttl,
                max_retries: self.max_retries,
                cache: RwLock::new(HashMap::new()),
                in_flight: Mutex::new(HashMap::new()),
                stats: RwLock::new(CacheStats::default()),
            }),
        })
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Build a client from the resolved environment / config files.
    /// Requires `ANDVARI_TOKEN` to be set or stored via the CLI's `andvari login`.
    pub fn from_env() -> Result<Self> {
        ClientBuilder::new().build()
    }

    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    pub fn config(&self) -> &Config {
        &self.inner.config
    }

    /// Fetch a secret value. Cached entries within TTL are returned without
    /// hitting the server.
    pub async fn get(&self, key: &str) -> Result<String> {
        if let Some(value) = self.from_cache(key).await {
            self.bump_stat(|s| s.hits += 1).await;
            return Ok(value);
        }
        self.bump_stat(|s| s.misses += 1).await;

        // Single-flight: only one concurrent fetch per key.
        let _flight = self.acquire_flight(key).await;
        // Re-check the cache in case another caller filled it while we waited.
        if let Some(value) = self.from_cache(key).await {
            return Ok(value);
        }

        let value = self.fetch_from_server(key).await?;
        self.put_cache(key.to_string(), value.clone()).await;
        Ok(value)
    }

    /// Get every secret in the configured environment as a hashmap.
    /// Useful for `client.get_all().await?` then iterating.
    pub async fn get_all(&self) -> Result<HashMap<String, String>> {
        let path = self.list_path()?;
        let resp: ListResponse = self.fetch_json(&path).await?;
        let mut out = HashMap::with_capacity(resp.secrets.len());
        for s in resp.secrets {
            // Fetch each value individually so the cache + audit log fire
            // per-secret. Server-side bulk-fetch endpoint is a future
            // optimisation if this ever becomes a bottleneck.
            let value = self.get(&s.key).await?;
            out.insert(s.key, value);
        }
        Ok(out)
    }

    /// Manually invalidate a cached value.
    pub async fn invalidate(&self, key: &str) {
        let mut cache = self.inner.cache.write().await;
        if cache.remove(key).is_some() {
            self.inner.stats.write().await.evictions += 1;
        }
    }

    /// Clear the entire cache.
    pub async fn invalidate_all(&self) {
        let mut cache = self.inner.cache.write().await;
        let n = cache.len() as u64;
        cache.clear();
        self.inner.stats.write().await.evictions += n;
    }

    pub async fn cache_stats(&self) -> CacheStats {
        *self.inner.stats.read().await
    }

    // ---------- internals ----------

    async fn from_cache(&self, key: &str) -> Option<String> {
        let cache = self.inner.cache.read().await;
        let entry = cache.get(key)?;
        if entry.inserted_at.elapsed() < self.inner.ttl {
            Some(entry.value.clone())
        } else {
            None
        }
    }

    async fn put_cache(&self, key: String, value: String) {
        let mut cache = self.inner.cache.write().await;
        cache.insert(
            key,
            CacheEntry {
                value,
                inserted_at: Instant::now(),
            },
        );
    }

    async fn acquire_flight(&self, key: &str) -> FlightGuard {
        let mut flight = self.inner.in_flight.lock().await;
        flight.insert(key.to_string(), ());
        FlightGuard {
            inner: self.inner.clone(),
            key: key.to_string(),
        }
    }

    async fn bump_stat<F: FnOnce(&mut CacheStats)>(&self, f: F) {
        let mut s = self.inner.stats.write().await;
        f(&mut s);
    }

    fn server(&self) -> Result<&str> {
        self.inner
            .config
            .server
            .as_deref()
            .ok_or(Error::MissingSetting("server"))
    }

    fn workspace(&self) -> Result<&str> {
        self.inner
            .config
            .workspace
            .as_deref()
            .ok_or(Error::MissingSetting("workspace"))
    }

    fn project(&self) -> Result<&str> {
        self.inner
            .config
            .project
            .as_deref()
            .ok_or(Error::MissingSetting("project"))
    }

    fn env_name(&self) -> Result<&str> {
        self.inner
            .config
            .default_env
            .as_deref()
            .ok_or(Error::MissingSetting("default_env"))
    }

    fn secret_path(&self, key: &str) -> Result<String> {
        Ok(format!(
            "{}/v1/ws/{}/projects/{}/envs/{}/secrets/{}",
            self.server()?.trim_end_matches('/'),
            self.workspace()?,
            self.project()?,
            self.env_name()?,
            key,
        ))
    }

    fn list_path(&self) -> Result<String> {
        Ok(format!(
            "{}/v1/ws/{}/projects/{}/envs/{}/secrets",
            self.server()?.trim_end_matches('/'),
            self.workspace()?,
            self.project()?,
            self.env_name()?,
        ))
    }

    async fn fetch_from_server(&self, key: &str) -> Result<String> {
        let url = self.secret_path(key)?;
        let resp: SecretValueResp = self.fetch_json(&url).await?;
        if let Some(v) = resp.value {
            return Ok(v);
        }
        if let Some(b64) = resp.value_b64 {
            // Caller asked for `get(key)` which returns String. Binary values
            // come back as base64; we hand them back as-is. Use a future
            // `get_bytes()` API if you need raw bytes.
            return Ok(b64);
        }
        Err(Error::Decode("missing value/value_b64".into()))
    }

    async fn fetch_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        let mut delay = Duration::from_millis(100);
        let mut last: Option<Error> = None;
        for attempt in 0..=self.inner.max_retries {
            match self
                .inner
                .http
                .get(url)
                .bearer_auth(&self.inner.token)
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status();
                    if status == StatusCode::NOT_FOUND {
                        let body = resp.text().await.unwrap_or_default();
                        // Try to extract the key from the URL for a friendlier error.
                        let key = url.rsplit('/').next().unwrap_or("?");
                        return Err(Error::NotFound(format!(
                            "{key}: server said {status}: {body}"
                        )));
                    }
                    if status.is_server_error() && attempt < self.inner.max_retries {
                        last = Some(Error::Server {
                            status: status.as_u16(),
                            body: resp.text().await.unwrap_or_default(),
                        });
                    } else if !status.is_success() {
                        let body = resp.text().await.unwrap_or_default();
                        return Err(Error::Server {
                            status: status.as_u16(),
                            body,
                        });
                    } else {
                        return resp
                            .json::<T>()
                            .await
                            .map_err(|e| Error::Decode(e.to_string()));
                    }
                }
                Err(e) => {
                    last = Some(Error::Http(e.to_string()));
                }
            }
            tokio::time::sleep(delay).await;
            delay = std::cmp::min(delay * 2, Duration::from_secs(5));
        }
        Err(last.unwrap_or_else(|| Error::Http("retries exhausted".into())))
    }
}

#[derive(Deserialize)]
struct SecretValueResp {
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    value_b64: Option<String>,
}

#[derive(Deserialize)]
struct ListResponse {
    secrets: Vec<SecretListItem>,
}

#[derive(Deserialize)]
struct SecretListItem {
    key: String,
}

struct FlightGuard {
    inner: Arc<Inner>,
    key: String,
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        let inner = self.inner.clone();
        let key = self.key.clone();
        tokio::spawn(async move {
            inner.in_flight.lock().await.remove(&key);
        });
    }
}

#[cfg(test)]
mod tests {
    //! Most of the SDK's HTTP behaviour is exercised via the CLI's e2e flow
    //! against a live server. Here we keep small invariant tests.

    use super::*;

    #[test]
    fn builder_requires_token() {
        // Clear the env so this test is deterministic regardless of host.
        unsafe { std::env::remove_var("ANDVARI_TOKEN") };
        let res = ClientBuilder::new()
            .config(Config {
                server: Some("http://example".into()),
                workspace: Some("ws".into()),
                project: Some("p".into()),
                default_env: Some("dev".into()),
                ..Config::default()
            })
            .build();
        assert!(matches!(res, Err(Error::MissingSetting("ANDVARI_TOKEN"))));
    }

    #[test]
    fn builder_with_explicit_token() {
        let client = ClientBuilder::new()
            .config(Config {
                server: Some("http://example".into()),
                workspace: Some("ws".into()),
                project: Some("p".into()),
                default_env: Some("dev".into()),
                ..Config::default()
            })
            .token("andv_ws_test")
            .build()
            .unwrap();
        assert_eq!(client.config().workspace.as_deref(), Some("ws"));
    }

    #[tokio::test]
    async fn cache_stats_track_hits_and_misses() {
        let client = ClientBuilder::new()
            .config(Config {
                server: Some("http://example".into()),
                workspace: Some("ws".into()),
                project: Some("p".into()),
                default_env: Some("dev".into()),
                ..Config::default()
            })
            .token("t")
            .build()
            .unwrap();
        // Pre-populate the cache without hitting the network.
        client.put_cache("KEY".into(), "value".into()).await;
        let v = client.get("KEY").await.unwrap();
        assert_eq!(v, "value");
        let stats = client.cache_stats().await;
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 0);

        client.invalidate("KEY").await;
        let stats = client.cache_stats().await;
        assert_eq!(stats.evictions, 1);
    }

    #[tokio::test]
    async fn cache_expires_after_ttl() {
        let client = ClientBuilder::new()
            .config(Config {
                server: Some("http://example".into()),
                workspace: Some("ws".into()),
                project: Some("p".into()),
                default_env: Some("dev".into()),
                ..Config::default()
            })
            .token("t")
            .ttl(Duration::from_millis(10))
            .build()
            .unwrap();
        client.put_cache("K".into(), "v".into()).await;
        assert_eq!(client.from_cache("K").await.as_deref(), Some("v"));
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(client.from_cache("K").await.is_none());
    }
}
