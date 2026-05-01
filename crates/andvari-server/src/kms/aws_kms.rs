//! AWS KMS provider for sealing the Root Key.
//!
//! Configured with `ANDVARI_KMS_AWS_KEY_ID` (a key ARN, alias, or key id).
//! Uses the standard AWS credential chain — operators set
//! `AWS_REGION` / `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (or use an
//! IAM role attached to the host).
//!
//! Wrapped form: the raw ciphertext blob bytes returned by KMS Encrypt.

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_kms::primitives::Blob;

use andvari_core::crypto::RootKey;
use andvari_core::seal::kms::{KmsBackend, KmsError, RK_PLAINTEXT_LEN, root_key_from_plaintext};

#[derive(Clone)]
pub struct AwsKms {
    client: KmsClient,
    key_id: String,
}

impl AwsKms {
    pub async fn from_env() -> Result<Option<Self>, KmsError> {
        let key_id = match std::env::var("ANDVARI_KMS_AWS_KEY_ID") {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let mut loader = aws_config::defaults(BehaviorVersion::latest());
        if let Ok(region) = std::env::var("ANDVARI_KMS_AWS_REGION") {
            loader = loader.region(aws_sdk_kms::config::Region::new(region));
        }
        let cfg = loader.load().await;
        Ok(Some(Self {
            client: KmsClient::new(&cfg),
            key_id,
        }))
    }
}

#[async_trait]
impl KmsBackend for AwsKms {
    async fn wrap(&self, plaintext: &[u8; RK_PLAINTEXT_LEN]) -> Result<Vec<u8>, KmsError> {
        let resp = self
            .client
            .encrypt()
            .key_id(&self.key_id)
            .plaintext(Blob::new(plaintext.to_vec()))
            .send()
            .await
            .map_err(|e| KmsError::Provider(format!("KMS Encrypt: {e}")))?;
        let blob = resp
            .ciphertext_blob
            .ok_or(KmsError::Shape("KMS Encrypt response missing ciphertext_blob"))?;
        Ok(blob.into_inner())
    }

    async fn unwrap(&self, wrapped: &[u8]) -> Result<RootKey, KmsError> {
        let resp = self
            .client
            .decrypt()
            .ciphertext_blob(Blob::new(wrapped.to_vec()))
            .key_id(&self.key_id)
            .send()
            .await
            .map_err(|e| KmsError::Provider(format!("KMS Decrypt: {e}")))?;
        let plaintext = resp
            .plaintext
            .ok_or(KmsError::Shape("KMS Decrypt response missing plaintext"))?;
        root_key_from_plaintext(plaintext.into_inner())
    }
}
