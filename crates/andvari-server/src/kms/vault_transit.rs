//! HashiCorp Vault Transit secrets engine as an Andvari KMS backend.
//!
//! API used:
//!
//! - `POST {addr}/v1/transit/encrypt/{key}` with `{"plaintext": "<base64>"}`
//!   returns `{"data": {"ciphertext": "vault:v1:..."}}`.
//! - `POST {addr}/v1/transit/decrypt/{key}` with `{"ciphertext": "vault:v1:..."}`
//!   returns `{"data": {"plaintext": "<base64>"}}`.
//!
//! Auth: `X-Vault-Token` header (HCP / Vault token, never logged).
//!
//! The wrapped form returned by [`VaultTransit::wrap`] is the UTF-8 bytes
//! of the `vault:v1:...` string. Callers persist these bytes verbatim.

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::Client;
use serde::Deserialize;
use url::Url;
use zeroize::Zeroize;

use andvari_core::crypto::RootKey;
use andvari_core::seal::kms::{KmsBackend, KmsError, RK_PLAINTEXT_LEN, root_key_from_plaintext};

#[derive(Clone)]
pub struct VaultTransit {
    client: Client,
    base: Url,
    token: String,
    key_name: String,
}

impl VaultTransit {
    /// Build a new Vault Transit backend.
    ///
    /// `addr` is the Vault address (e.g. `https://vault.example.com`),
    /// `token` is a Vault token with `transit/encrypt/{key}` and
    /// `transit/decrypt/{key}` capabilities, and `key_name` is the name
    /// of the Transit key Andvari will use to wrap its Root Key.
    pub fn new(
        addr: &str,
        token: impl Into<String>,
        key_name: impl Into<String>,
    ) -> Result<Self, KmsError> {
        let base = Url::parse(addr)
            .map_err(|e| KmsError::Transport(format!("invalid vault addr: {e}")))?;
        Ok(Self {
            client: Client::builder()
                .user_agent(concat!("andvari/", env!("CARGO_PKG_VERSION")))
                .build()
                .map_err(|e| KmsError::Transport(e.to_string()))?,
            base,
            token: token.into(),
            key_name: key_name.into(),
        })
    }

    /// For tests: inject a custom HTTP client (so wiremock-driven tests can
    /// hit a local mock server with any URL).
    #[cfg(test)]
    fn with_client(
        client: Client,
        addr: &str,
        token: &str,
        key_name: &str,
    ) -> Result<Self, KmsError> {
        Ok(Self {
            client,
            base: Url::parse(addr)
                .map_err(|e| KmsError::Transport(format!("invalid vault addr: {e}")))?,
            token: token.to_string(),
            key_name: key_name.to_string(),
        })
    }

    fn endpoint(&self, op: &str) -> Result<Url, KmsError> {
        self.base
            .join(&format!("v1/transit/{}/{}", op, self.key_name))
            .map_err(|e| KmsError::Transport(format!("bad endpoint url: {e}")))
    }
}

#[async_trait]
impl KmsBackend for VaultTransit {
    async fn wrap(&self, plaintext: &[u8; RK_PLAINTEXT_LEN]) -> Result<Vec<u8>, KmsError> {
        let url = self.endpoint("encrypt")?;
        let body = serde_json::json!({
            "plaintext": STANDARD.encode(plaintext),
        });
        let resp = self
            .client
            .post(url)
            .header("X-Vault-Token", &self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| KmsError::Transport(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(KmsError::Provider(format!("HTTP {status}: {body}")));
        }
        let parsed: VaultEncryptResponse = resp
            .json()
            .await
            .map_err(|_| KmsError::Shape("response was not the expected JSON shape"))?;
        Ok(parsed.data.ciphertext.into_bytes())
    }

    async fn unwrap(&self, wrapped: &[u8]) -> Result<RootKey, KmsError> {
        let url = self.endpoint("decrypt")?;
        let ciphertext = std::str::from_utf8(wrapped)
            .map_err(|_| KmsError::Shape("wrapped blob is not valid UTF-8 vault:v1:... text"))?;
        let body = serde_json::json!({ "ciphertext": ciphertext });
        let resp = self
            .client
            .post(url)
            .header("X-Vault-Token", &self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| KmsError::Transport(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(KmsError::Provider(format!("HTTP {status}: {body}")));
        }
        let parsed: VaultDecryptResponse = resp
            .json()
            .await
            .map_err(|_| KmsError::Shape("response was not the expected JSON shape"))?;
        let mut plaintext_b64 = parsed.data.plaintext;
        let plaintext = STANDARD
            .decode(plaintext_b64.as_bytes())
            .map_err(KmsError::Base64)?;
        plaintext_b64.zeroize();
        root_key_from_plaintext(plaintext)
    }
}

#[derive(Deserialize)]
struct VaultEncryptResponse {
    data: VaultEncryptData,
}

#[derive(Deserialize)]
struct VaultEncryptData {
    ciphertext: String,
}

#[derive(Deserialize)]
struct VaultDecryptResponse {
    data: VaultDecryptData,
}

#[derive(Deserialize)]
struct VaultDecryptData {
    plaintext: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn build_backend(server: &MockServer) -> VaultTransit {
        let client = reqwest::Client::new();
        VaultTransit::with_client(client, &server.uri(), "hvs.test-token", "andvari").unwrap()
    }

    #[tokio::test]
    async fn wrap_posts_correct_request_and_parses_response() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/transit/encrypt/andvari"))
            .and(header("X-Vault-Token", "hvs.test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "ciphertext": "vault:v1:abc123==" }
            })))
            .mount(&server)
            .await;

        let kms = build_backend(&server);
        let wrapped = kms.wrap(&[0xaa; 32]).await.unwrap();
        assert_eq!(wrapped, b"vault:v1:abc123==");
    }

    #[tokio::test]
    async fn unwrap_returns_root_key() {
        let server = MockServer::start().await;
        let plaintext_bytes = [0x55u8; 32];
        let plaintext_b64 = STANDARD.encode(plaintext_bytes);

        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/andvari"))
            .and(header("X-Vault-Token", "hvs.test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "plaintext": plaintext_b64 }
            })))
            .mount(&server)
            .await;

        let kms = build_backend(&server);
        // Bytes can be anything; unwrap forwards them as ciphertext to Vault.
        let _rk = kms.unwrap(b"vault:v1:abc123==").await.unwrap();
        // We don't have a public RootKey accessor — the lack of error +
        // construction success is the contract this test cares about.
    }

    #[tokio::test]
    async fn provider_error_surfaces_status_and_body() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/transit/encrypt/andvari"))
            .respond_with(ResponseTemplate::new(403).set_body_string("permission denied"))
            .mount(&server)
            .await;

        let kms = build_backend(&server);
        let err = kms.wrap(&[0u8; 32]).await.unwrap_err();
        match err {
            KmsError::Provider(msg) => {
                assert!(msg.contains("403"));
                assert!(msg.contains("permission denied"));
            }
            other => panic!("expected Provider error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_response_is_shape_error() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/transit/encrypt/andvari"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "wrong": "shape"
            })))
            .mount(&server)
            .await;

        let kms = build_backend(&server);
        assert!(matches!(
            kms.wrap(&[0u8; 32]).await,
            Err(KmsError::Shape(_))
        ));
    }

    #[tokio::test]
    async fn round_trip_via_real_inverse_mock() {
        // Mount both encrypt and decrypt, where decrypt returns whatever
        // plaintext was implied by the most recent encrypt. We approximate
        // this by having decrypt always return a specific plaintext and
        // checking that wrap+unwrap produces a coherent flow.
        let server = MockServer::start().await;
        let plaintext = [0x77u8; 32];
        let plaintext_b64 = STANDARD.encode(plaintext);

        Mock::given(method("POST"))
            .and(path("/v1/transit/encrypt/andvari"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "ciphertext": "vault:v1:dummy" }
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/andvari"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "plaintext": plaintext_b64 }
            })))
            .mount(&server)
            .await;

        let kms = build_backend(&server);
        let wrapped = kms.wrap(&plaintext).await.unwrap();
        assert_eq!(wrapped, b"vault:v1:dummy");
        let _ = kms.unwrap(&wrapped).await.unwrap();
    }
}
