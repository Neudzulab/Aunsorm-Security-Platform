//! Production webhook implementation for OAuth token revocation events
//!
//! Implements Aunsorm-specific webhook delivery with HMAC-SHA256 signature
//! verification and configurable timeouts.

use crate::config::RevocationWebhookConfig;
use crate::error::ServerError;
use aunsorm_core::AunsormNativeRng;
use hmac::{Hmac, Mac};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::borrow::ToOwned;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;
type Result<T> = std::result::Result<T, ServerError>;

/// Revocation event payload
#[derive(Debug, Serialize, Deserialize)]
pub struct RevocationEventPayload {
    /// Event type
    pub event: String,
    /// Event timestamp (Unix epoch milliseconds)
    #[serde(rename = "timestampMs")]
    pub timestamp_ms: u64,
    /// Revocation details
    pub revocation: RevocationDetails,
}

/// Details about the revoked token
#[derive(Debug, Serialize, Deserialize)]
pub struct RevocationDetails {
    /// Token identifier hash (SHA256 hex)
    #[serde(rename = "tokenHash")]
    pub token_hash: String,
    /// Token type (`access_token` or `refresh_token`)
    #[serde(rename = "tokenType")]
    pub token_type: String,
    /// Whether the token was successfully revoked
    pub revoked: bool,
    /// Client ID (if available)
    #[serde(rename = "clientId", skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Client context for downstream auditing
    #[serde(rename = "client", skip_serializing_if = "Option::is_none")]
    pub client_context: Option<ClientContext>,
    /// Revoked at timestamp (same as parent `timestamp_ms`)
    #[serde(rename = "revokedAtMs")]
    pub revoked_at_ms: u64,
}

/// Additional context about the client and session attached to the revoked token
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ClientContext {
    /// OAuth client identifier
    #[serde(rename = "id")]
    pub id: String,
    /// Optional subject associated with the session
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Role granted for the session
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Scopes issued to the token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Whether multi-factor authentication was verified
    #[serde(rename = "mfaVerified", skip_serializing_if = "Option::is_none")]
    pub mfa_verified: Option<bool>,
}

/// Webhook client for sending revocation events
pub struct WebhookClient {
    config: Arc<RevocationWebhookConfig>,
    http_client: reqwest::Client,
}

impl WebhookClient {
    /// Creates a new webhook client with the provided configuration
    ///
    /// # Errors
    /// Returns error if HTTP client initialization fails
    pub fn new(config: Arc<RevocationWebhookConfig>) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(config.timeout())
            .build()
            .map_err(|err| {
                ServerError::Configuration(format!("HTTP client oluşturulamadı: {err}"))
            })?;

        Ok(Self {
            config,
            http_client,
        })
    }

    /// Sends a revocation event to the configured webhook endpoint
    ///
    /// # Errors
    /// Returns error if:
    /// - Payload serialization fails
    /// - HMAC signature generation fails
    /// - HTTP request fails
    /// - Remote server returns non-2xx status
    pub async fn send_revocation_event(
        &self,
        _issuer: &str,
        token_identifier: &str,
        token_type: &str,
        client_id: Option<&str>,
        client_context: Option<ClientContext>,
    ) -> Result<()> {
        #[allow(clippy::cast_possible_truncation)]
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| ServerError::Configuration(format!("Sistem zamanı alınamadı: {err}")))?
            .as_millis() as u64;

        // Hash the token identifier
        use sha2::Digest;
        let token_hash = if token_identifier.len() == 64
            && token_identifier.chars().all(|c| c.is_ascii_hexdigit())
        {
            // Already a hash
            token_identifier.to_string()
        } else {
            // Hash it
            let mut hasher = Sha256::new();
            hasher.update(token_identifier.as_bytes());
            hex::encode(hasher.finalize())
        };

        let client_id = client_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);

        let event = RevocationEventPayload {
            event: "token.revoked".to_string(),
            timestamp_ms,
            revocation: RevocationDetails {
                token_hash,
                token_type: token_type.to_string(),
                revoked: true,
                client_id: client_id.map(ToOwned::to_owned),
                client_context,
                revoked_at_ms: timestamp_ms,
            },
        };

        let payload = serde_json::to_vec(&event).map_err(|err| {
            ServerError::Configuration(format!("Payload serialize edilemedi: {err}"))
        })?;

        let (signature_header, nonce) = self.compute_signature_header(&payload, timestamp_ms)?;

        let response = self
            .http_client
            .post(self.config.endpoint().clone())
            .header("Content-Type", "application/json")
            .header("Aunsorm-Signature", signature_header)
            .header("X-Webhook-Nonce", nonce)
            .body(payload)
            .send()
            .await
            .map_err(|err| {
                ServerError::Configuration(format!("Webhook isteği gönderilemedi: {err}"))
            })?;

        if !response.status().is_success() {
            return Err(ServerError::Configuration(format!(
                "Webhook başarısız oldu: HTTP {}",
                response.status()
            )));
        }

        Ok(())
    }

    /// Computes HMAC-SHA256 signature header for webhook payload verification
    /// Format: t=<timestamp>;nonce=<nonce>;v1=<signature>
    fn compute_signature_header(
        &self,
        payload: &[u8],
        timestamp_ms: u64,
    ) -> Result<(String, String)> {
        // Generate random nonce using Aunsorm Native RNG
        let mut rng = AunsormNativeRng::new();
        let mut nonce_bytes = [0u8; 16];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);

        // Create signing payload: timestamp.nonce.body
        let signing_payload = format!("{timestamp_ms}.{nonce}.");
        let mut signing_data = signing_payload.into_bytes();
        signing_data.extend_from_slice(payload);

        let mut mac = HmacSha256::new_from_slice(self.config.secret().as_bytes())
            .map_err(|err| ServerError::Configuration(format!("HMAC oluşturulamadı: {err}")))?;

        mac.update(&signing_data);
        let result = mac.finalize();
        let signature = hex::encode(result.into_bytes());

        let header = format!("t={timestamp_ms};nonce={nonce};v1={signature}");
        Ok((header, nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use url::Url;

    #[test]
    fn compute_signature_is_deterministic() {
        let config = RevocationWebhookConfig::new(
            Url::parse("https://example.com/webhook").unwrap(),
            "test-secret-12345678901234567890123456789012",
            Duration::from_secs(5),
        )
        .unwrap();

        let client = WebhookClient::new(Arc::new(config)).unwrap();
        let payload = b"test payload";

        let (sig1, nonce1) = client
            .compute_signature_header(payload, 1_234_567_890)
            .unwrap();
        let (sig2, nonce2) = client
            .compute_signature_header(payload, 1_234_567_890)
            .unwrap();

        // Signatures will differ due to random nonce
        assert_ne!(sig1, sig2);
        assert_ne!(nonce1, nonce2);

        assert!(sig1.contains("t=1234567890"));
        assert!(sig1.contains("v1="));
        assert!(sig1.contains("nonce="));
    }

    #[test]
    fn event_serialization_produces_valid_json() {
        let event = RevocationEventPayload {
            event: "token.revoked".to_string(),
            timestamp_ms: 1_234_567_890,
            revocation: RevocationDetails {
                token_hash: "abc123".to_string(),
                token_type: "access_token".to_string(),
                revoked: true,
                client_id: Some("demo-client".to_string()),
                client_context: Some(ClientContext {
                    id: "demo-client".to_string(),
                    subject: Some("alice".to_string()),
                    role: Some("user".to_string()),
                    scope: Some("read:all".to_string()),
                    mfa_verified: Some(true),
                }),
                revoked_at_ms: 1_234_567_890,
            },
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event\":\"token.revoked\""));
        assert!(json.contains("\"timestampMs\":1234567890"));
        assert!(json.contains("\"tokenHash\":\"abc123\""));
        assert!(json.contains("\"tokenType\":\"access_token\""));
        assert!(json.contains("\"revoked\":true"));
        assert!(json.contains("\"clientId\":\"demo-client\""));
        assert!(json.contains("\"client\":{\"id\":\"demo-client\""));
        assert!(json.contains("\"subject\":\"alice\""));
        assert!(json.contains("\"role\":\"user\""));
        assert!(json.contains("\"scope\":\"read:all\""));
        assert!(json.contains("\"mfaVerified\":true"));
    }
}
