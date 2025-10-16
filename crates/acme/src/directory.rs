use std::{borrow::ToOwned, collections::BTreeMap};

use serde_json::{Map, Value};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum AcmeDirectoryError {
    #[error("directory belgesi JSON olarak ayrıştırılamadı: {0}")]
    Json(#[from] serde_json::Error),
    #[error("directory belgesi bir JSON objesi olmalı")]
    NotAnObject,
    #[error("`{0}` alanı bulunamadı")]
    MissingField(&'static str),
    #[error("`{field}` alanı geçersiz URL: {source}")]
    InvalidUrl {
        field: String,
        source: url::ParseError,
    },
    #[error("`{field}` alanı string tipinde olmalı")]
    InvalidUrlType { field: String },
    #[error("`meta.{field}` alanı beklenen türde değil")]
    InvalidMetaField { field: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KnownEndpoint {
    NewNonce,
    NewAccount,
    NewOrder,
    RevokeCert,
    KeyChange,
    NewAuthz,
    RenewalInfo,
}

impl KnownEndpoint {
    const fn as_key(self) -> &'static str {
        match self {
            Self::NewNonce => "newNonce",
            Self::NewAccount => "newAccount",
            Self::NewOrder => "newOrder",
            Self::RevokeCert => "revokeCert",
            Self::KeyChange => "keyChange",
            Self::NewAuthz => "newAuthz",
            Self::RenewalInfo => "renewalInfo",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeDirectory {
    pub new_nonce: Url,
    pub new_account: Url,
    pub new_order: Url,
    pub revoke_cert: Url,
    pub key_change: Url,
    pub new_authz: Option<Url>,
    pub renewal_info: Option<Url>,
    pub meta: Option<AcmeDirectoryMeta>,
    pub additional_endpoints: BTreeMap<String, Url>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeDirectoryMeta {
    pub terms_of_service: Option<Url>,
    pub website: Option<Url>,
    pub caa_identities: Vec<String>,
    pub external_account_required: bool,
}

impl AcmeDirectory {
    /// ACME directory JSON belgesini tip güvenli yapılara dönüştürür.
    ///
    /// # Errors
    ///
    /// JSON objesi beklenen şemayı karşılamadığında veya zorunlu alanlar
    /// geçersiz URL içerdiğinde `AcmeDirectoryError` döndürülür.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, AcmeDirectoryError> {
        let value: Value = serde_json::from_slice(bytes)?;
        Self::from_json_value(value)
    }

    /// Serde JSON değerinden directory örneği oluşturur.
    ///
    /// # Errors
    ///
    /// JSON objesi beklenen şemayı karşılamadığında veya zorunlu alanlar
    /// geçersiz URL içerdiğinde `AcmeDirectoryError` döndürülür.
    pub fn from_json_value(value: Value) -> Result<Self, AcmeDirectoryError> {
        match value {
            Value::Object(map) => Self::from_object(&map),
            _ => Err(AcmeDirectoryError::NotAnObject),
        }
    }

    /// JSON metninden directory örneği oluşturur.
    ///
    /// # Errors
    ///
    /// JSON ayrıştırılamadığında veya beklenen şemayı sağlamadığında
    /// `AcmeDirectoryError` döner.
    pub fn from_json_str(text: &str) -> Result<Self, AcmeDirectoryError> {
        let value: Value = serde_json::from_str(text)?;
        Self::from_json_value(value)
    }

    #[must_use]
    pub fn endpoint(&self, name: &str) -> Option<&Url> {
        match name {
            key if key == KnownEndpoint::NewNonce.as_key() => Some(&self.new_nonce),
            key if key == KnownEndpoint::NewAccount.as_key() => Some(&self.new_account),
            key if key == KnownEndpoint::NewOrder.as_key() => Some(&self.new_order),
            key if key == KnownEndpoint::RevokeCert.as_key() => Some(&self.revoke_cert),
            key if key == KnownEndpoint::KeyChange.as_key() => Some(&self.key_change),
            key if key == KnownEndpoint::NewAuthz.as_key() => self.new_authz.as_ref(),
            key if key == KnownEndpoint::RenewalInfo.as_key() => self.renewal_info.as_ref(),
            _ => self.additional_endpoints.get(name),
        }
    }

    #[must_use]
    pub const fn additional_endpoints(&self) -> &BTreeMap<String, Url> {
        &self.additional_endpoints
    }

    fn from_object(object: &Map<String, Value>) -> Result<Self, AcmeDirectoryError> {
        let new_nonce = parse_required_url(object, KnownEndpoint::NewNonce.as_key())?;
        let new_account = parse_required_url(object, KnownEndpoint::NewAccount.as_key())?;
        let new_order = parse_required_url(object, KnownEndpoint::NewOrder.as_key())?;
        let revoke_cert = parse_required_url(object, KnownEndpoint::RevokeCert.as_key())?;
        let key_change = parse_required_url(object, KnownEndpoint::KeyChange.as_key())?;
        let new_authz = parse_optional_url(object, KnownEndpoint::NewAuthz.as_key())?;
        let renewal_info = parse_optional_url(object, KnownEndpoint::RenewalInfo.as_key())?;
        let meta = parse_meta(object)?;
        let additional_endpoints = collect_additional_endpoints(object)?;

        Ok(Self {
            new_nonce,
            new_account,
            new_order,
            revoke_cert,
            key_change,
            new_authz,
            renewal_info,
            meta,
            additional_endpoints,
        })
    }
}

fn parse_required_url(
    object: &Map<String, Value>,
    key: &'static str,
) -> Result<Url, AcmeDirectoryError> {
    match object.get(key) {
        Some(Value::String(value)) => {
            Url::parse(value).map_err(|source| AcmeDirectoryError::InvalidUrl {
                field: key.to_owned(),
                source,
            })
        }
        Some(_) => Err(AcmeDirectoryError::InvalidUrlType {
            field: key.to_owned(),
        }),
        None => Err(AcmeDirectoryError::MissingField(key)),
    }
}

fn parse_optional_url(
    object: &Map<String, Value>,
    key: &'static str,
) -> Result<Option<Url>, AcmeDirectoryError> {
    match object.get(key) {
        Some(Value::String(value)) => {
            Url::parse(value)
                .map(Some)
                .map_err(|source| AcmeDirectoryError::InvalidUrl {
                    field: key.to_owned(),
                    source,
                })
        }
        Some(_) => Err(AcmeDirectoryError::InvalidUrlType {
            field: key.to_owned(),
        }),
        None => Ok(None),
    }
}

fn parse_meta(
    object: &Map<String, Value>,
) -> Result<Option<AcmeDirectoryMeta>, AcmeDirectoryError> {
    let Some(raw_meta) = object.get("meta") else {
        return Ok(None);
    };
    let meta_object = raw_meta
        .as_object()
        .ok_or(AcmeDirectoryError::InvalidMetaField { field: "meta" })?;

    let terms_of_service = parse_meta_url(meta_object, "termsOfService")?;
    let website = parse_meta_url(meta_object, "website")?;
    let caa_identities = match meta_object.get("caaIdentities") {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect(),
        Some(_) => {
            return Err(AcmeDirectoryError::InvalidMetaField {
                field: "caaIdentities",
            });
        }
        None => Vec::new(),
    };
    let external_account_required = match meta_object.get("externalAccountRequired") {
        Some(Value::Bool(flag)) => *flag,
        Some(_) => {
            return Err(AcmeDirectoryError::InvalidMetaField {
                field: "externalAccountRequired",
            });
        }
        None => false,
    };

    Ok(Some(AcmeDirectoryMeta {
        terms_of_service,
        website,
        caa_identities,
        external_account_required,
    }))
}

fn parse_meta_url(
    object: &Map<String, Value>,
    key: &'static str,
) -> Result<Option<Url>, AcmeDirectoryError> {
    match object.get(key) {
        Some(Value::String(value)) => {
            Url::parse(value)
                .map(Some)
                .map_err(|source| AcmeDirectoryError::InvalidUrl {
                    field: format!("meta.{key}"),
                    source,
                })
        }
        Some(_) => Err(AcmeDirectoryError::InvalidMetaField { field: key }),
        None => Ok(None),
    }
}

fn collect_additional_endpoints(
    object: &Map<String, Value>,
) -> Result<BTreeMap<String, Url>, AcmeDirectoryError> {
    let mut additional = BTreeMap::new();
    for (key, value) in object {
        if matches!(
            key.as_str(),
            "meta"
                | "newNonce"
                | "newAccount"
                | "newOrder"
                | "revokeCert"
                | "keyChange"
                | "newAuthz"
                | "renewalInfo"
        ) {
            continue;
        }
        if let Value::String(url) = value {
            let parsed = Url::parse(url).map_err(|source| AcmeDirectoryError::InvalidUrl {
                field: key.clone(),
                source,
            })?;
            additional.insert(key.clone(), parsed);
        }
    }
    Ok(additional)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    const SAMPLE_DIRECTORY: &str = r#"{
        "newNonce": "https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce",
        "newAccount": "https://acme-staging-v02.api.letsencrypt.org/acme/new-account",
        "newOrder": "https://acme-staging-v02.api.letsencrypt.org/acme/new-order",
        "revokeCert": "https://acme-staging-v02.api.letsencrypt.org/acme/revoke-cert",
        "keyChange": "https://acme-staging-v02.api.letsencrypt.org/acme/key-change",
        "newAuthz": "https://acme-staging-v02.api.letsencrypt.org/acme/new-authz",
        "renewalInfo": "https://acme-staging-v02.api.letsencrypt.org/acme/renewal-info",
        "meta": {
            "termsOfService": "https://letsencrypt.org/documents/LE-SA-v1.4-April-15-2021.pdf",
            "website": "https://letsencrypt.org",
            "caaIdentities": ["letsencrypt.org"],
            "externalAccountRequired": false
        },
        "preAuthorizeDomain": "https://acme-staging-v02.api.letsencrypt.org/acme/pre-authorize",
        "challenge-v1": "https://acme-staging-v02.api.letsencrypt.org/acme/challenge-v1"
    }"#;

    #[test]
    fn parses_directory_and_meta() {
        let directory = AcmeDirectory::from_json_slice(SAMPLE_DIRECTORY.as_bytes()).unwrap();

        assert_eq!(
            directory.new_nonce,
            Url::parse("https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce").unwrap()
        );
        assert_eq!(
            directory.endpoint("preAuthorizeDomain").unwrap(),
            &Url::parse("https://acme-staging-v02.api.letsencrypt.org/acme/pre-authorize").unwrap()
        );
        assert_eq!(directory.additional_endpoints.len(), 2);
        let meta = directory.meta.unwrap();
        assert_eq!(meta.caa_identities, vec!["letsencrypt.org".to_string()]);
        assert_eq!(meta.external_account_required, false);
        assert_eq!(
            meta.terms_of_service.unwrap(),
            Url::parse("https://letsencrypt.org/documents/LE-SA-v1.4-April-15-2021.pdf").unwrap()
        );
    }

    #[test]
    fn missing_required_field() {
        let json = br#"{"newNonce": "https://example.com/nonce"}"#;
        let error = AcmeDirectory::from_json_slice(json).unwrap_err();
        match error {
            AcmeDirectoryError::MissingField(field) => assert_eq!(field, "newAccount"),
            other => panic!("beklenmeyen hata: {other:?}"),
        }
    }

    #[test]
    fn invalid_required_url_type_raises_error() {
        let json = br#"{
            "newNonce": 42,
            "newAccount": "https://example.com/new-account",
            "newOrder": "https://example.com/new-order",
            "revokeCert": "https://example.com/revoke",
            "keyChange": "https://example.com/key-change"
        }"#;
        let error = AcmeDirectory::from_json_slice(json).unwrap_err();
        match error {
            AcmeDirectoryError::InvalidUrlType { field } => {
                assert_eq!(field, "newNonce".to_owned());
            }
            other => panic!("beklenmeyen hata: {other:?}"),
        }
    }

    #[test]
    fn invalid_meta_field_type() {
        let json = br#"{
            "newNonce": "https://example.com/new-nonce",
            "newAccount": "https://example.com/new-account",
            "newOrder": "https://example.com/new-order",
            "revokeCert": "https://example.com/revoke",
            "keyChange": "https://example.com/key-change",
            "meta": {"caaIdentities": 42}
        }"#;
        let error = AcmeDirectory::from_json_slice(json).unwrap_err();
        match error {
            AcmeDirectoryError::InvalidMetaField { field } => assert_eq!(field, "caaIdentities"),
            other => panic!("beklenmeyen hata: {other:?}"),
        }
    }

    #[test]
    fn from_json_str_matches_slice() {
        let from_slice = AcmeDirectory::from_json_slice(SAMPLE_DIRECTORY.as_bytes()).unwrap();
        let from_str = AcmeDirectory::from_json_str(SAMPLE_DIRECTORY).unwrap();
        assert_eq!(from_slice, from_str);
    }

    #[test]
    fn from_json_value_rejects_non_objects() {
        let value = serde_json::json!(["not", "an", "object"]);
        let err = AcmeDirectory::from_json_value(value).unwrap_err();
        assert!(matches!(err, AcmeDirectoryError::NotAnObject));
    }
}
