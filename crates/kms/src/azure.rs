use std::collections::HashMap;
use std::convert::TryFrom;
use std::io;
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::warn;
use url::Url;
use zeroize::Zeroizing;

use crate::config::{AzureBackendConfig, AzureKeyConfig, BackendKind};
use crate::error::{KmsError, Result};
use crate::util::compute_kid;

pub struct AzureBackend {
    client: Client,
    base_url: String,
    token: Option<Zeroizing<String>>,
    max_retries: usize,
    backoff: Duration,
    keys: HashMap<String, AzureKeyEntry>,
}

struct AzureKeyEntry {
    signer: AzureSigner,
    cache: Mutex<AzureCache>,
}

enum AzureSigner {
    Remote { resource: String },
    Local { signing: SigningKey },
}

#[derive(Default)]
struct AzureCache {
    public_key: Option<[u8; 32]>,
    kid: Option<String>,
}

#[derive(Debug)]
struct HttpError {
    status: StatusCode,
    message: String,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "http status {}: {}", self.status, self.message)
    }
}

impl std::error::Error for HttpError {}

enum RetryError {
    Retry(KmsError),
    Abort(KmsError),
}

#[derive(Serialize)]
struct SignRequest {
    algorithm: &'static str,
    message: String,
}

#[derive(Deserialize)]
struct SignResponse {
    signature: String,
    #[serde(default)]
    public_key: Option<String>,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Deserialize)]
struct KeyResponse {
    public_key: String,
    #[serde(default)]
    kid: Option<String>,
}

impl AzureBackend {
    pub(crate) fn new(config: AzureBackendConfig, strict: bool) -> Result<Self> {
        let base_url = normalize_base_url(&config.base_url)?;
        let client = Client::builder()
            .build()
            .map_err(|err| KmsError::Config(format!("failed to build http client: {err}")))?;
        let token = config.access_token.map(Zeroizing::new);
        let backoff = Duration::from_millis(config.retry_backoff_ms.max(1));

        let mut keys = HashMap::new();
        for key in config.keys {
            let alias = key.key_id.trim();
            if alias.is_empty() {
                return Err(KmsError::Config("azure key_id cannot be empty".into()));
            }
            if keys.contains_key(alias) {
                return Err(KmsError::Config(format!(
                    "duplicate azure key identifier detected: {alias}"
                )));
            }
            let signer = build_signer(&key)?;
            let mut cache = AzureCache::default();
            if let Some(public) = initial_public(&signer, &key, strict)? {
                cache.public_key = Some(public.value);
                cache.kid = Some(public.kid);
            }
            let entry = AzureKeyEntry {
                signer,
                cache: Mutex::new(cache),
            };
            keys.insert(alias.to_string(), entry);
        }

        Ok(Self {
            client,
            base_url,
            token,
            max_retries: config.max_retries,
            backoff,
            keys,
        })
    }

    pub(crate) fn sign_ed25519(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let entry = self.entry_for(key_id)?;
        match &entry.signer {
            AzureSigner::Local { signing } => Ok(signing.sign(message).to_vec()),
            AzureSigner::Remote { resource } => {
                let url = format!("{}/{}/sign", self.base_url, resource);
                let request = SignRequest {
                    algorithm: "EdDSA",
                    message: STANDARD.encode(message),
                };
                let response: SignResponse = self.post_json(&url, &request, resource, key_id)?;
                let signature_bytes = STANDARD
                    .decode(response.signature.as_bytes())
                    .map_err(|err| KmsError::unavailable(BackendKind::Azure, err))?;
                if signature_bytes.len() != 64 {
                    return Err(KmsError::unavailable(
                        BackendKind::Azure,
                        HttpError {
                            status: StatusCode::BAD_GATEWAY,
                            message: format!(
                                "azure signature for {key_id} must be 64 bytes, got {}",
                                signature_bytes.len()
                            ),
                        },
                    ));
                }
                if response.public_key.is_some() || response.kid.is_some() {
                    update_cache(entry, response.public_key, response.kid, resource)?;
                }
                Ok(signature_bytes)
            }
        }
    }

    pub(crate) fn public_ed25519(&self, key_id: &str) -> Result<Vec<u8>> {
        let entry = self.entry_for(key_id)?;
        let public = match &entry.signer {
            AzureSigner::Local { signing } => ensure_local_public(entry, signing)?,
            AzureSigner::Remote { resource } => {
                self.ensure_remote_public(entry, resource, key_id)?
            }
        };
        Ok(public.to_vec())
    }

    pub(crate) fn key_kid(&self, key_id: &str) -> Result<String> {
        let entry = self.entry_for(key_id)?;
        {
            let cache = lock_cache(&entry.cache, BackendKind::Azure)?;
            if let Some(kid) = &cache.kid {
                return Ok(kid.clone());
            }
        }
        let public = match &entry.signer {
            AzureSigner::Local { signing } => ensure_local_public(entry, signing)?,
            AzureSigner::Remote { resource } => {
                self.ensure_remote_public(entry, resource, key_id)?
            }
        };
        let kid = compute_kid(&public);
        lock_cache(&entry.cache, BackendKind::Azure)?
            .kid
            .get_or_insert_with(|| kid.clone());
        Ok(kid)
    }

    fn ensure_remote_public(
        &self,
        entry: &AzureKeyEntry,
        resource: &str,
        key_id: &str,
    ) -> Result<[u8; 32]> {
        {
            let cache = lock_cache(&entry.cache, BackendKind::Azure)?;
            if let Some(public) = cache.public_key {
                return Ok(public);
            }
        }
        let url = format!("{}/{}", self.base_url, resource);
        let response: KeyResponse = self.get_json(&url, resource, key_id)?;
        update_cache(entry, Some(response.public_key), response.kid, resource)?;
        let cache = lock_cache(&entry.cache, BackendKind::Azure)?;
        cache.public_key.ok_or_else(|| {
            KmsError::unavailable(
                BackendKind::Azure,
                HttpError {
                    status: StatusCode::BAD_GATEWAY,
                    message: format!("azure backend did not return public key for {resource}"),
                },
            )
        })
    }

    fn post_json<T, R>(&self, url: &str, body: &T, resource: &str, key_id: &str) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        self.retrying(|attempt| {
            let mut request = self.client.post(url);
            if let Some(token) = &self.token {
                request = request.bearer_auth(token.as_str());
            }
            let response = request.json(body).send();
            self.process_response(response, resource, key_id, attempt)
        })
    }

    fn get_json<R>(&self, url: &str, resource: &str, key_id: &str) -> Result<R>
    where
        R: for<'de> Deserialize<'de>,
    {
        self.retrying(|attempt| {
            let mut request = self.client.get(url);
            if let Some(token) = &self.token {
                request = request.bearer_auth(token.as_str());
            }
            let response = request.send();
            self.process_response(response, resource, key_id, attempt)
        })
    }

    fn process_response<R>(
        &self,
        response: reqwest::Result<reqwest::blocking::Response>,
        resource: &str,
        key_id: &str,
        attempt: usize,
    ) -> std::result::Result<R, RetryError>
    where
        R: for<'de> Deserialize<'de>,
    {
        match response {
            Ok(resp) => self.handle_success(resp, resource, key_id, attempt),
            Err(err) => Err(RetryError::Retry(KmsError::unavailable(
                BackendKind::Azure,
                err,
            ))),
        }
    }

    fn handle_success<R>(
        &self,
        resp: reqwest::blocking::Response,
        resource: &str,
        key_id: &str,
        attempt: usize,
    ) -> std::result::Result<R, RetryError>
    where
        R: for<'de> Deserialize<'de>,
    {
        let status = resp.status();
        if status.is_success() {
            return resp
                .json()
                .map_err(|err| RetryError::Abort(KmsError::unavailable(BackendKind::Azure, err)));
        }
        if status == StatusCode::NOT_FOUND {
            return Err(RetryError::Abort(KmsError::KeyNotFound {
                backend: BackendKind::Azure,
                key_id: key_id.to_string(),
            }));
        }
        let message_body = resp.text().unwrap_or_default();
        let message = if message_body.is_empty() {
            format!("azure backend error for {resource}")
        } else {
            format!("azure backend error for {resource}: {message_body}")
        };
        let error = HttpError { status, message };
        if should_retry(status) && attempt < self.max_retries {
            Err(RetryError::Retry(KmsError::unavailable(
                BackendKind::Azure,
                error,
            )))
        } else {
            Err(RetryError::Abort(KmsError::unavailable(
                BackendKind::Azure,
                error,
            )))
        }
    }

    fn retrying<F, R>(&self, mut operation: F) -> Result<R>
    where
        F: FnMut(usize) -> std::result::Result<R, RetryError>,
    {
        let mut attempt = 0;
        loop {
            match operation(attempt) {
                Ok(result) => return Ok(result),
                Err(RetryError::Abort(err)) => return Err(err),
                Err(RetryError::Retry(err)) => {
                    if attempt >= self.max_retries {
                        return Err(err);
                    }
                    thread::sleep(self.sleep_duration(attempt));
                    attempt += 1;
                }
            }
        }
    }

    fn sleep_duration(&self, attempt: usize) -> Duration {
        let shift = u32::try_from(attempt).unwrap_or(u32::MAX).min(16);
        let factor = f64::from(1_u32 << shift);
        self.backoff.mul_f64(factor)
    }

    fn entry_for(&self, key_id: &str) -> Result<&AzureKeyEntry> {
        self.keys.get(key_id).ok_or_else(|| KmsError::KeyNotFound {
            backend: BackendKind::Azure,
            key_id: key_id.to_string(),
        })
    }
}

struct InitialPublic {
    value: [u8; 32],
    kid: String,
}

fn build_signer(key: &AzureKeyConfig) -> Result<AzureSigner> {
    if let Some(secret_b64) = &key.local_private_key {
        let decoded = STANDARD.decode(secret_b64.as_bytes()).map_err(|err| {
            KmsError::Config(format!(
                "failed to decode azure private key for {}: {err}",
                key.key_id
            ))
        })?;
        let seed: [u8; 32] = decoded.try_into().map_err(|_| {
            KmsError::Config(format!(
                "azure private key for {} must be 32 bytes",
                key.key_id
            ))
        })?;
        let signing = SigningKey::from_bytes(&seed);
        Ok(AzureSigner::Local { signing })
    } else {
        let resource = determine_resource(key)?;
        Ok(AzureSigner::Remote { resource })
    }
}

fn initial_public(
    signer: &AzureSigner,
    key: &AzureKeyConfig,
    strict: bool,
) -> Result<Option<InitialPublic>> {
    if let Some(public_b64) = &key.public_key {
        let decoded = STANDARD.decode(public_b64.as_bytes()).map_err(|err| {
            KmsError::Config(format!(
                "failed to decode azure public key for {}: {err}",
                key.key_id
            ))
        })?;
        let public = decode_public_config(decoded, &key.key_id)?;
        let kid = key.kid.clone().unwrap_or_else(|| compute_kid(&public));
        return Ok(Some(InitialPublic { value: public, kid }));
    }

    match signer {
        AzureSigner::Local { signing } => {
            if strict {
                return Err(KmsError::Config(format!(
                    "strict mode requires explicit public_key for {}",
                    key.key_id
                )));
            }
            let verifying = VerifyingKey::from(signing);
            let public = verifying.to_bytes();
            warn!(
                key = key.key_id,
                "azure backend using local fallback public key"
            );
            let kid = key.kid.clone().unwrap_or_else(|| compute_kid(&public));
            Ok(Some(InitialPublic { value: public, kid }))
        }
        AzureSigner::Remote { .. } => {
            if strict {
                return Err(KmsError::Config(format!(
                    "strict mode requires public_key for azure key {}",
                    key.key_id
                )));
            }
            warn!(
                key = key.key_id,
                "azure backend missing public key; will fetch from remote"
            );
            Ok(None)
        }
    }
}

fn determine_resource(key: &AzureKeyConfig) -> Result<String> {
    if let Some(resource) = &key.resource {
        let trimmed = resource.trim_matches('/');
        if trimmed.is_empty() {
            return Err(KmsError::Config(format!(
                "azure resource for {} cannot be empty",
                key.key_id
            )));
        }
        return Ok(trimmed.to_string());
    }
    let name = key
        .key_name
        .as_deref()
        .ok_or_else(|| KmsError::Config(format!("azure key_name required for {}", key.key_id)))?;
    let version = key.key_version.as_deref().ok_or_else(|| {
        KmsError::Config(format!("azure key_version required for {}", key.key_id))
    })?;
    Ok(format!("keys/{name}/{version}"))
}

fn normalize_base_url(raw: &str) -> Result<String> {
    let url = Url::parse(raw)
        .map_err(|err| KmsError::Config(format!("invalid azure base url: {err}")))?;
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn decode_public_config(bytes: Vec<u8>, key_id: &str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| KmsError::Config(format!("public key for Azure:{key_id} must be 32 bytes")))
}

fn decode_public_runtime(bytes: Vec<u8>, resource: &str) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        KmsError::unavailable(
            BackendKind::Azure,
            HttpError {
                status: StatusCode::BAD_GATEWAY,
                message: format!("azure backend returned invalid public key for {resource}"),
            },
        )
    })
}

fn ensure_local_public(entry: &AzureKeyEntry, signing: &SigningKey) -> Result<[u8; 32]> {
    {
        let cache = lock_cache(&entry.cache, BackendKind::Azure)?;
        if let Some(public) = cache.public_key {
            return Ok(public);
        }
    }

    let verifying = VerifyingKey::from(signing);
    let public = verifying.to_bytes();
    let kid = compute_kid(&public);
    {
        let mut cache = lock_cache(&entry.cache, BackendKind::Azure)?;
        cache.public_key.get_or_insert(public);
        cache.kid.get_or_insert_with(|| kid.clone());
    }
    Ok(public)
}

fn update_cache(
    entry: &AzureKeyEntry,
    public: Option<String>,
    kid: Option<String>,
    resource: &str,
) -> Result<()> {
    let decoded_public = if let Some(public_b64) = public {
        let bytes = STANDARD
            .decode(public_b64.as_bytes())
            .map_err(|err| KmsError::unavailable(BackendKind::Azure, err))?;
        Some(decode_public_runtime(bytes, resource)?)
    } else {
        None
    };

    {
        let mut cache = lock_cache(&entry.cache, BackendKind::Azure)?;
        if let Some(public) = decoded_public {
            cache.public_key = Some(public);
            cache.kid.get_or_insert_with(|| compute_kid(&public));
        }
        if let Some(kid_value) = kid {
            cache.kid = Some(kid_value);
        }
    }
    Ok(())
}

fn should_retry(status: StatusCode) -> bool {
    status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS
}

fn lock_cache(
    cache: &Mutex<AzureCache>,
    backend: BackendKind,
) -> Result<MutexGuard<'_, AzureCache>> {
    cache
        .lock()
        .map_err(|_| KmsError::unavailable(backend, io::Error::other("azure cache poisoned")))
}
