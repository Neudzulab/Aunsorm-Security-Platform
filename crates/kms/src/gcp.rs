use std::collections::HashMap;
use std::convert::TryFrom;
use std::io;
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use crate::config::BackendKind;
use crate::config::{GcpBackendConfig, GcpKeyConfig};
use crate::error::{KmsError, Result};
use crate::util::compute_kid;

pub struct GcpBackend {
    client: Client,
    base_url: String,
    token: Option<Zeroizing<String>>,
    max_retries: usize,
    backoff: Duration,
    keys: HashMap<String, GcpKeyEntry>,
}

struct GcpKeyEntry {
    resource: String,
    cache: Mutex<GcpCache>,
}

#[derive(Default)]
struct GcpCache {
    public_key: Option<[u8; 32]>,
    kid: Option<String>,
}

enum RetryError {
    Retry(KmsError),
    Abort(KmsError),
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

#[derive(Serialize)]
struct SignRequest {
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
struct PublicResponse {
    public_key: String,
    #[serde(default)]
    kid: Option<String>,
}

impl GcpBackend {
    pub fn new(config: GcpBackendConfig) -> Result<Self> {
        let base_url = normalize_base_url(&config.base_url)?;
        let client = Client::builder()
            .no_proxy()
            .build()
            .map_err(|err| KmsError::Config(format!("failed to build http client: {err}")))?;

        let token = config.access_token.map(Zeroizing::new);
        let backoff = Duration::from_millis(config.retry_backoff_ms.max(1));
        let mut keys = HashMap::new();
        for key in config.keys {
            let alias = key.key_id.trim();
            if alias.is_empty() {
                return Err(KmsError::Config("gcp key_id cannot be empty".into()));
            }
            if keys.contains_key(alias) {
                return Err(KmsError::Config(format!(
                    "duplicate gcp key identifier detected: {alias}"
                )));
            }
            let resource = determine_resource(alias, &key)?;
            let cache = initial_cache(&key)?;
            keys.insert(
                alias.to_string(),
                GcpKeyEntry {
                    resource,
                    cache: Mutex::new(cache),
                },
            );
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
        let url = format!("{}/v1/{}:signEd25519", self.base_url, entry.resource);
        let request = SignRequest {
            message: STANDARD.encode(message),
        };
        let response: SignResponse = self.post_json(&url, &request, key_id)?;
        let signature_bytes = STANDARD
            .decode(response.signature.as_bytes())
            .map_err(|err| KmsError::unavailable(BackendKind::Gcp, err))?;
        if signature_bytes.len() != 64 {
            return Err(KmsError::unavailable(
                BackendKind::Gcp,
                HttpError {
                    status: StatusCode::OK,
                    message: format!(
                        "gcp signature for {key_id} must be 64 bytes, got {}",
                        signature_bytes.len()
                    ),
                },
            ));
        }
        if response.public_key.is_some() || response.kid.is_some() {
            update_cache(entry, response.public_key, response.kid, &entry.resource)?;
        }
        Ok(signature_bytes)
    }

    pub(crate) fn public_ed25519(&self, key_id: &str) -> Result<Vec<u8>> {
        let entry = self.entry_for(key_id)?;
        let public = self.ensure_public(entry, key_id)?;
        Ok(public.to_vec())
    }

    pub(crate) fn key_kid(&self, key_id: &str) -> Result<String> {
        let entry = self.entry_for(key_id)?;
        {
            let cache = lock_cache(&entry.cache)?;
            if let Some(kid) = &cache.kid {
                return Ok(kid.clone());
            }
        }
        let public = self.ensure_public(entry, key_id)?;
        let kid = compute_kid(&public);
        {
            let mut cache = lock_cache(&entry.cache)?;
            cache.kid.get_or_insert_with(|| kid.clone());
        }
        Ok(kid)
    }

    fn ensure_public(&self, entry: &GcpKeyEntry, key_id: &str) -> Result<[u8; 32]> {
        {
            let cache = lock_cache(&entry.cache)?;
            if let Some(public) = cache.public_key {
                return Ok(public);
            }
        }
        let url = format!("{}/v1/{}", self.base_url, entry.resource);
        let response: PublicResponse = self.get_json(&url, key_id)?;
        update_cache(
            entry,
            Some(response.public_key),
            response.kid,
            &entry.resource,
        )?;
        let cache = lock_cache(&entry.cache)?;
        cache.public_key.ok_or_else(|| {
            KmsError::unavailable(
                BackendKind::Gcp,
                HttpError {
                    status: StatusCode::BAD_GATEWAY,
                    message: format!(
                        "gcp backend did not return public key for {}",
                        entry.resource
                    ),
                },
            )
        })
    }

    fn post_json<T, R>(&self, url: &str, body: &T, key_id: &str) -> Result<R>
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
            self.process_response(response, key_id, attempt)
        })
    }

    fn get_json<R>(&self, url: &str, key_id: &str) -> Result<R>
    where
        R: for<'de> Deserialize<'de>,
    {
        self.retrying(|attempt| {
            let mut request = self.client.get(url);
            if let Some(token) = &self.token {
                request = request.bearer_auth(token.as_str());
            }
            let response = request.send();
            self.process_response(response, key_id, attempt)
        })
    }

    fn process_response<R>(
        &self,
        response: reqwest::Result<reqwest::blocking::Response>,
        key_id: &str,
        attempt: usize,
    ) -> std::result::Result<R, RetryError>
    where
        R: for<'de> Deserialize<'de>,
    {
        match response {
            Ok(resp) => self.handle_success(resp, key_id, attempt),
            Err(err) => Err(RetryError::Retry(KmsError::unavailable(
                BackendKind::Gcp,
                err,
            ))),
        }
    }

    fn handle_success<R>(
        &self,
        resp: reqwest::blocking::Response,
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
                .map_err(|err| RetryError::Abort(KmsError::unavailable(BackendKind::Gcp, err)));
        }
        if status == StatusCode::NOT_FOUND {
            return Err(RetryError::Abort(KmsError::KeyNotFound {
                backend: BackendKind::Gcp,
                key_id: key_id.to_string(),
            }));
        }
        let message = resp.text().unwrap_or_default();
        let error = HttpError { status, message };
        if should_retry(status) && attempt < self.max_retries {
            Err(RetryError::Retry(KmsError::unavailable(
                BackendKind::Gcp,
                error,
            )))
        } else {
            Err(RetryError::Abort(KmsError::unavailable(
                BackendKind::Gcp,
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

    fn entry_for(&self, key_id: &str) -> Result<&GcpKeyEntry> {
        self.keys.get(key_id).ok_or_else(|| KmsError::KeyNotFound {
            backend: BackendKind::Gcp,
            key_id: key_id.to_string(),
        })
    }
}

fn normalize_base_url(raw: &str) -> Result<String> {
    let url =
        Url::parse(raw).map_err(|err| KmsError::Config(format!("invalid gcp base url: {err}")))?;
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn determine_resource(alias: &str, key: &GcpKeyConfig) -> Result<String> {
    let resource = key.resource.as_ref().map_or_else(
        || alias.to_string(),
        |value| value.trim_matches('/').to_string(),
    );
    if resource.is_empty() {
        return Err(KmsError::Config(format!(
            "gcp resource for {alias} cannot be empty"
        )));
    }
    Ok(resource)
}

fn initial_cache(key: &GcpKeyConfig) -> Result<GcpCache> {
    let mut cache = GcpCache::default();
    if let Some(public_b64) = &key.public_key {
        let decoded = STANDARD.decode(public_b64.as_bytes()).map_err(|err| {
            KmsError::Config(format!(
                "failed to decode gcp public key for {}: {err}",
                key.key_id
            ))
        })?;
        let public = decode_public_config(decoded, &key.key_id)?;
        let kid = key.kid.clone().unwrap_or_else(|| compute_kid(&public));
        cache.public_key = Some(public);
        cache.kid = Some(kid);
    } else if let Some(kid) = &key.kid {
        cache.kid = Some(kid.clone());
    }
    Ok(cache)
}

fn decode_public_config(bytes: Vec<u8>, key_id: &str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| KmsError::Config(format!("public key for Gcp:{key_id} must be 32 bytes")))
}

fn decode_public_runtime(bytes: Vec<u8>, resource: &str) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        KmsError::unavailable(
            BackendKind::Gcp,
            HttpError {
                status: StatusCode::BAD_GATEWAY,
                message: format!("gcp backend returned invalid public key for {resource}"),
            },
        )
    })
}

fn lock_cache(cache: &Mutex<GcpCache>) -> Result<MutexGuard<'_, GcpCache>> {
    cache.lock().map_err(|_| {
        KmsError::unavailable(BackendKind::Gcp, io::Error::other("gcp cache poisoned"))
    })
}

fn should_retry(status: StatusCode) -> bool {
    status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS
}

fn update_cache(
    entry: &GcpKeyEntry,
    public: Option<String>,
    kid: Option<String>,
    resource: &str,
) -> Result<()> {
    let decoded_public = if let Some(public_b64) = public {
        let bytes = STANDARD
            .decode(public_b64.as_bytes())
            .map_err(|err| KmsError::unavailable(BackendKind::Gcp, err))?;
        Some(decode_public_runtime(bytes, resource)?)
    } else {
        None
    };

    {
        let mut cache = lock_cache(&entry.cache)?;
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
