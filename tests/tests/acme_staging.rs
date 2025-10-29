use std::env;

use anyhow::{anyhow, Context, Result};
use aunsorm_acme::{
    AcmeDirectory, Ed25519AccountKey, KeyBinding, ReplayNonce, REPLAY_NONCE_HEADER,
};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use reqwest::header::{HeaderMap, ACCEPT, CONTENT_TYPE, LOCATION, USER_AGENT};
use reqwest::Client;
use serde_json::json;
use tokio::time::timeout;
use url::Url;

const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const USER_AGENT_VALUE: &str = "aunsorm-acme-staging-smoke/0.1";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ACME staging credentials"]
async fn acme_staging_account_roundtrip() -> Result<()> {
    let directory_url = match read_env("ACME_STAGING_DIRECTORY") {
        Some(value) => value,
        None => {
            eprintln!("[acme-staging] Skipping: ACME_STAGING_DIRECTORY env var is not configured.");
            return Ok(());
        }
    };

    let account_key_seed = match read_env("ACME_STAGING_ACCOUNT_KEY") {
        Some(value) => value,
        None => {
            eprintln!(
                "[acme-staging] Skipping: ACME_STAGING_ACCOUNT_KEY env var is not configured."
            );
            return Ok(());
        }
    };

    let contact_entries = match read_env("ACME_STAGING_CONTACT") {
        Some(value) => value,
        None => {
            eprintln!("[acme-staging] Skipping: ACME_STAGING_CONTACT env var is not configured.");
            return Ok(());
        }
    };

    let directory_url = Url::parse(&directory_url).context("invalid ACME directory URL")?;
    let contact_values = parse_contacts(&contact_entries)?;
    let account_key = Ed25519AccountKey::from_seed(decode_seed(&account_key_seed)?);

    let client = Client::builder()
        .user_agent(USER_AGENT_VALUE)
        .build()
        .context("failed to build reqwest client")?;

    let directory: AcmeDirectory = timeout(
        HTTP_TIMEOUT,
        client
            .get(directory_url.as_str())
            .header(ACCEPT, "application/json")
            .send(),
    )
    .await
    .context("directory request timed out")??
    .error_for_status()
    .context("ACME directory request returned error status")?
    .json()
    .await
    .context("failed to decode ACME directory response")?;

    let nonce_response = timeout(
        HTTP_TIMEOUT,
        client.get(directory.new_nonce.as_str()).send(),
    )
    .await
    .context("new-nonce request timed out")??
    .error_for_status()
    .context("new-nonce request returned error status")?;
    let mut nonce = parse_nonce(nonce_response.headers())
        .context("failed to parse replay nonce from new-nonce response")?;

    let new_account_payload = json!({
        "termsOfServiceAgreed": true,
        "contact": contact_values,
    });
    let new_account_url =
        Url::parse(directory.new_account.as_str()).context("failed to parse new-account URL")?;
    let account_jws = account_key
        .sign_json(
            &new_account_payload,
            &nonce,
            &new_account_url,
            KeyBinding::Jwk,
        )
        .context("failed to sign new-account request")?;

    let account_response = post_jws(&client, new_account_url.as_str(), &account_jws).await?;
    let account_headers = account_response.headers().clone();
    let kid_header = account_headers
        .get(LOCATION)
        .ok_or_else(|| anyhow!("ACME new-account response missing Location header"))?;
    let kid = kid_header
        .to_str()
        .context("failed to decode Location header")?
        .to_owned();
    nonce = parse_nonce(&account_headers)
        .context("failed to parse replay nonce from new-account response")?;

    let account_body: serde_json::Value = account_response
        .json()
        .await
        .context("failed to parse new-account response body")?;
    let status = account_body
        .get("status")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    assert!(
        matches!(status, "valid" | "active" | "pending"),
        "unexpected ACME account status: {status}"
    );

    let kid_url = Url::parse(&kid).context("failed to parse account Location URL")?;
    let account_lookup_jws = account_key
        .sign_payload(b"", &nonce, &kid_url, KeyBinding::Kid(&kid))
        .context("failed to sign account lookup request")?;

    let account_lookup_response = post_jws(&client, kid_url.as_str(), &account_lookup_jws).await?;
    let lookup_headers = account_lookup_response.headers().clone();
    parse_nonce(&lookup_headers).context("account lookup response missing replay nonce header")?;
    let lookup_body: serde_json::Value = account_lookup_response
        .json()
        .await
        .context("failed to parse account lookup response body")?;

    assert_eq!(
        lookup_body
            .get("contact")
            .and_then(|value| value.as_array())
            .map(|values| values.len())
            .unwrap_or_default(),
        contact_values.len(),
        "ACME account contact list differs from configuration"
    );

    Ok(())
}

fn read_env(name: &str) -> Option<String> {
    let value = env::var(name).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn decode_seed(value: &str) -> Result<[u8; 32]> {
    let compact: String = value.split_whitespace().collect();
    let decoded = STANDARD
        .decode(&compact)
        .or_else(|_| STANDARD_NO_PAD.decode(&compact))
        .or_else(|_| URL_SAFE_NO_PAD.decode(&compact))
        .context("failed to base64 decode ACME staging account key seed")?;
    if decoded.len() != 32 {
        return Err(anyhow!(
            "ACME staging account key seed must be 32 bytes, got {} bytes",
            decoded.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&decoded);
    Ok(seed)
}

fn parse_contacts(raw: &str) -> Result<Vec<String>> {
    let mut contacts = Vec::new();
    for entry in raw.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !(trimmed.starts_with("mailto:") || trimmed.starts_with("tel:")) {
            return Err(anyhow!(
                "ACME staging contact must start with mailto: or tel:, got {trimmed}"
            ));
        }
        contacts.push(trimmed.to_owned());
    }

    if contacts.is_empty() {
        return Err(anyhow!(
            "ACME staging contact configuration produced an empty contact list"
        ));
    }

    Ok(contacts)
}

fn parse_nonce(headers: &HeaderMap) -> Result<ReplayNonce> {
    let value = headers
        .get(REPLAY_NONCE_HEADER)
        .ok_or_else(|| anyhow!("{REPLAY_NONCE_HEADER} header missing"))?;
    let as_str = value
        .to_str()
        .context("failed to decode replay nonce header value")?;
    ReplayNonce::parse(as_str).context("failed to parse replay nonce value")
}

async fn post_jws(
    client: &Client,
    url: &str,
    jws: &aunsorm_acme::AcmeJws,
) -> Result<reqwest::Response> {
    timeout(
        HTTP_TIMEOUT,
        client
            .post(url)
            .header(CONTENT_TYPE, "application/jose+json")
            .header(USER_AGENT, USER_AGENT_VALUE)
            .json(jws)
            .send(),
    )
    .await
    .context("ACME JWS request timed out")??
    .error_for_status()
    .with_context(|| format!("ACME request to {url} returned error status"))
}
