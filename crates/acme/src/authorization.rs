use std::fmt;

use serde_json::{Map, Value};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use url::Url;

use crate::order::{OrderIdentifier, OrderIdentifierError};

/// ACME yetkilendirme kaynağını ayrıştırırken oluşabilecek hatalar.
#[derive(Debug, Error)]
pub enum AuthorizationError {
    /// JSON değeri bir nesne değil.
    #[error("ACME authorization belgesi JSON objesi olmalıdır")]
    NotAnObject,
    /// Zorunlu alan eksik.
    #[error("ACME authorization alanı eksik: {field}")]
    MissingField {
        /// Eksik alan adı.
        field: &'static str,
    },
    /// Alan beklenen türde değil.
    #[error("ACME authorization alanı beklenen türde değil: {field}")]
    InvalidFieldType {
        /// Hatalı alan adı.
        field: &'static str,
    },
    /// Authorization durum değeri bilinmeyen bir string.
    #[error("ACME authorization durum değeri geçersiz: {value}")]
    InvalidStatus {
        /// Geçersiz durum değeri.
        value: String,
    },
    /// Tarih alanı RFC 3339 formatında değil.
    #[error("ACME authorization tarih alanı geçersiz: {field}")]
    InvalidDate {
        /// Hatalı alan adı.
        field: &'static str,
    },
    /// Identifier üretimi sırasında hata oluştu.
    #[error(transparent)]
    Identifier(#[from] OrderIdentifierError),
    /// Identifier `type` alanı desteklenmiyor.
    #[error("ACME authorization identifier türü desteklenmiyor: {value}")]
    UnsupportedIdentifierType {
        /// Bilinmeyen identifier türü.
        value: String,
    },
    /// Hiç challenge sağlanmadı.
    #[error("ACME authorization en az bir challenge içermelidir")]
    MissingChallenges,
    /// Challenge ayrıştırılırken hata oluştu.
    #[error("ACME authorization challenge[{index}] hatası: {source}")]
    Challenge {
        /// Hatanın oluştuğu challenge indeksi.
        index: usize,
        /// Kaynak hata.
        #[source]
        source: ChallengeError,
    },
}

/// ACME challenge ayrıştırma hataları.
#[derive(Debug, Error)]
pub enum ChallengeError {
    /// JSON objesi beklenirken farklı türle karşılaşıldı.
    #[error("ACME challenge JSON objesi olmalıdır")]
    NotAnObject,
    /// Zorunlu alan eksik.
    #[error("ACME challenge alanı eksik: {field}")]
    MissingField {
        /// Eksik alan adı.
        field: &'static str,
    },
    /// Alan beklenen türde değil.
    #[error("ACME challenge alanı beklenen türde değil: {field}")]
    InvalidFieldType {
        /// Hatalı alan adı.
        field: &'static str,
    },
    /// Challenge tipi bilinmiyor.
    #[error("ACME challenge türü desteklenmiyor: {value}")]
    InvalidType {
        /// Hatalı tür değeri.
        value: String,
    },
    /// Challenge durumu bilinmiyor.
    #[error("ACME challenge durum değeri geçersiz: {value}")]
    InvalidStatus {
        /// Geçersiz durum değeri.
        value: String,
    },
    /// Challenge URL'i ayrıştırılamadı.
    #[error("ACME challenge URL'i geçersiz: {source}")]
    InvalidUrl {
        /// Kaynak URL ayrıştırma hatası.
        #[from]
        source: url::ParseError,
    },
    /// Challenge URL'i HTTPS kullanmıyor.
    #[error("ACME challenge URL'i HTTPS kullanmalıdır (şema: {scheme})")]
    InsecureUrl {
        /// Kullanılan şema.
        scheme: String,
    },
    /// Challenge token değeri RFC 8555 kurallarını karşılamıyor.
    #[error("ACME challenge token değeri geçersiz: {reason}")]
    InvalidToken {
        /// Geçersiz token sebebi.
        reason: &'static str,
    },
    /// `validated` alanı RFC 3339 formatında değil.
    #[error("ACME challenge validated tarihi geçersiz")]
    InvalidValidated,
}

/// Authorization kaynağının durumları.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationStatus {
    Pending,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}

impl AuthorizationStatus {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "valid" => Some(Self::Valid),
            "invalid" => Some(Self::Invalid),
            "deactivated" => Some(Self::Deactivated),
            "expired" => Some(Self::Expired),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

impl fmt::Display for AuthorizationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pending => "pending",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Deactivated => "deactivated",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        })
    }
}

/// Challenge durumları.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

impl ChallengeStatus {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "processing" => Some(Self::Processing),
            "valid" => Some(Self::Valid),
            "invalid" => Some(Self::Invalid),
            _ => None,
        }
    }
}

impl fmt::Display for ChallengeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pending => "pending",
            Self::Processing => "processing",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
        })
    }
}

/// ACME challenge türleri.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeKind {
    Http01,
    Dns01,
    TlsAlpn01,
    Other(String),
}

impl ChallengeKind {
    fn parse(value: &str) -> Self {
        match value {
            "http-01" => Self::Http01,
            "dns-01" => Self::Dns01,
            "tls-alpn-01" => Self::TlsAlpn01,
            other => Self::Other(other.to_owned()),
        }
    }

    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Http01 => "http-01",
            Self::Dns01 => "dns-01",
            Self::TlsAlpn01 => "tls-alpn-01",
            Self::Other(value) => value.as_str(),
        }
    }

    const fn requires_token(&self) -> bool {
        matches!(self, Self::Http01 | Self::Dns01 | Self::TlsAlpn01)
    }
}

/// ACME authorization kaynağı.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    identifier: OrderIdentifier,
    status: AuthorizationStatus,
    expires: Option<OffsetDateTime>,
    wildcard: bool,
    challenges: Vec<Challenge>,
}

impl Authorization {
    /// JSON değerinden authorization üretir.
    ///
    /// # Errors
    ///
    /// JSON objesi zorunlu alanları sağlamazsa veya beklenen türlere
    /// uymuyorsa `AuthorizationError` döndürülür.
    pub fn from_json_value(value: Value) -> Result<Self, AuthorizationError> {
        let Value::Object(object) = value else {
            return Err(AuthorizationError::NotAnObject);
        };
        Self::from_object(&object)
    }

    /// JSON metninden authorization üretir.
    ///
    /// # Errors
    ///
    /// JSON ayrıştırması veya alan doğrulaması başarısız olursa `AuthorizationError`
    /// döner.
    pub fn from_json_str(text: &str) -> Result<Self, AuthorizationError> {
        let value: Value =
            serde_json::from_str(text).map_err(|_| AuthorizationError::NotAnObject)?;
        Self::from_json_value(value)
    }

    /// JSON diliminden authorization üretir.
    ///
    /// # Errors
    ///
    /// JSON ayrıştırması veya alan doğrulaması başarısız olursa `AuthorizationError`
    /// döner.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, AuthorizationError> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| AuthorizationError::NotAnObject)?;
        Self::from_json_value(value)
    }

    fn from_object(object: &Map<String, Value>) -> Result<Self, AuthorizationError> {
        let status_value = match object.get("status") {
            Some(Value::String(value)) => value.clone(),
            Some(_) => return Err(AuthorizationError::InvalidFieldType { field: "status" }),
            None => return Err(AuthorizationError::MissingField { field: "status" }),
        };
        let status =
            AuthorizationStatus::parse(&status_value).ok_or(AuthorizationError::InvalidStatus {
                value: status_value,
            })?;

        let identifier_value =
            object
                .get("identifier")
                .ok_or(AuthorizationError::MissingField {
                    field: "identifier",
                })?;
        let identifier = parse_identifier(identifier_value)?;

        let expires = match object.get("expires") {
            Some(Value::String(value)) => Some(
                parse_datetime(value)
                    .map_err(|_| AuthorizationError::InvalidDate { field: "expires" })?,
            ),
            Some(Value::Null) | None => None,
            Some(_) => return Err(AuthorizationError::InvalidFieldType { field: "expires" }),
        };

        let wildcard = match object.get("wildcard") {
            Some(Value::Bool(value)) => *value,
            Some(Value::Null) | None => false,
            Some(_) => return Err(AuthorizationError::InvalidFieldType { field: "wildcard" }),
        };

        let challenges_value =
            object
                .get("challenges")
                .ok_or(AuthorizationError::MissingField {
                    field: "challenges",
                })?;
        let Value::Array(challenges_array) = challenges_value else {
            return Err(AuthorizationError::InvalidFieldType {
                field: "challenges",
            });
        };
        if challenges_array.is_empty() {
            return Err(AuthorizationError::MissingChallenges);
        }
        let mut challenges = Vec::with_capacity(challenges_array.len());
        for (index, challenge_value) in challenges_array.iter().enumerate() {
            let challenge = parse_challenge(challenge_value)
                .map_err(|source| AuthorizationError::Challenge { index, source })?;
            challenges.push(challenge);
        }

        Ok(Self {
            identifier,
            status,
            expires,
            wildcard,
            challenges,
        })
    }

    /// Authorization durumunu döndürür.
    #[must_use]
    pub const fn status(&self) -> AuthorizationStatus {
        self.status
    }

    /// Identifier değerini döndürür.
    #[must_use]
    pub const fn identifier(&self) -> &OrderIdentifier {
        &self.identifier
    }

    /// Süre sonu bilgisini döndürür.
    #[must_use]
    pub const fn expires(&self) -> Option<&OffsetDateTime> {
        self.expires.as_ref()
    }

    /// Wildcard bayrağını döndürür.
    #[must_use]
    pub const fn wildcard(&self) -> bool {
        self.wildcard
    }

    /// Challenge listesini döndürür.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn challenges(&self) -> &[Challenge] {
        &self.challenges
    }
}

/// ACME challenge temsili.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    kind: ChallengeKind,
    status: ChallengeStatus,
    url: Url,
    token: Option<String>,
    validated: Option<OffsetDateTime>,
}

impl Challenge {
    /// Challenge türünü döndürür.
    #[must_use]
    pub const fn kind(&self) -> &ChallengeKind {
        &self.kind
    }

    /// Challenge durumunu döndürür.
    #[must_use]
    pub const fn status(&self) -> ChallengeStatus {
        self.status
    }

    /// Challenge URL'ini döndürür.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// Challenge token değerini döndürür.
    #[must_use]
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// Challenge `validated` zamanını döndürür.
    #[must_use]
    pub const fn validated(&self) -> Option<&OffsetDateTime> {
        self.validated.as_ref()
    }
}

fn parse_identifier(value: &Value) -> Result<OrderIdentifier, AuthorizationError> {
    let Value::Object(object) = value else {
        return Err(AuthorizationError::InvalidFieldType {
            field: "identifier",
        });
    };

    let identifier_type = match object.get("type") {
        Some(Value::String(value)) => value.as_str(),
        Some(_) => {
            return Err(AuthorizationError::InvalidFieldType {
                field: "identifier.type",
            })
        }
        None => {
            return Err(AuthorizationError::MissingField {
                field: "identifier.type",
            })
        }
    };

    let identifier_value = match object.get("value") {
        Some(Value::String(value)) => value.as_str(),
        Some(_) => {
            return Err(AuthorizationError::InvalidFieldType {
                field: "identifier.value",
            })
        }
        None => {
            return Err(AuthorizationError::MissingField {
                field: "identifier.value",
            })
        }
    };

    match identifier_type {
        "dns" => Ok(OrderIdentifier::dns(identifier_value)?),
        "ip" => Ok(OrderIdentifier::ip(identifier_value)?),
        other => Err(AuthorizationError::UnsupportedIdentifierType {
            value: other.to_owned(),
        }),
    }
}

fn parse_challenge(value: &Value) -> Result<Challenge, ChallengeError> {
    let Value::Object(object) = value else {
        return Err(ChallengeError::NotAnObject);
    };

    let challenge_type_value = match object.get("type") {
        Some(Value::String(value)) => value.clone(),
        Some(_) => return Err(ChallengeError::InvalidFieldType { field: "type" }),
        None => return Err(ChallengeError::MissingField { field: "type" }),
    };
    let kind = ChallengeKind::parse(&challenge_type_value);

    let status_value = match object.get("status") {
        Some(Value::String(value)) => value.clone(),
        Some(_) => return Err(ChallengeError::InvalidFieldType { field: "status" }),
        None => return Err(ChallengeError::MissingField { field: "status" }),
    };
    let status = ChallengeStatus::parse(&status_value).ok_or(ChallengeError::InvalidStatus {
        value: status_value,
    })?;

    let url_value = match object.get("url") {
        Some(Value::String(value)) => value,
        Some(_) => return Err(ChallengeError::InvalidFieldType { field: "url" }),
        None => return Err(ChallengeError::MissingField { field: "url" }),
    };
    let url = Url::parse(url_value)?;
    if url.scheme() != "https" {
        return Err(ChallengeError::InsecureUrl {
            scheme: url.scheme().to_owned(),
        });
    }

    let token = match object.get("token") {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Null) | None => None,
        Some(_) => return Err(ChallengeError::InvalidFieldType { field: "token" }),
    };

    if kind.requires_token() {
        let token_value = token
            .as_deref()
            .ok_or(ChallengeError::MissingField { field: "token" })?;
        validate_token(token_value)?;
    } else if let Some(token_value) = token.as_deref() {
        validate_token(token_value)?;
    }

    let validated = match object.get("validated") {
        Some(Value::String(value)) => {
            Some(parse_datetime(value).map_err(|_| ChallengeError::InvalidValidated)?)
        }
        Some(Value::Null) | None => None,
        Some(_) => return Err(ChallengeError::InvalidFieldType { field: "validated" }),
    };

    Ok(Challenge {
        kind,
        status,
        url,
        token,
        validated,
    })
}

fn parse_datetime(value: &str) -> Result<OffsetDateTime, time::error::Parse> {
    OffsetDateTime::parse(value, &Rfc3339)
}

fn validate_token(value: &str) -> Result<(), ChallengeError> {
    if value.len() < 16 {
        return Err(ChallengeError::InvalidToken {
            reason: "token çok kısa",
        });
    }
    if value.len() > 128 {
        return Err(ChallengeError::InvalidToken {
            reason: "token çok uzun",
        });
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        return Err(ChallengeError::InvalidToken {
            reason: "token base64url karakterleri dışındakiler içeriyor",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use time::macros::datetime;

    #[test]
    fn parses_authorization_with_http_challenge() {
        let json_value = json!({
            "status": "pending",
            "expires": "2024-07-01T12:00:00Z",
            "identifier": {"type": "dns", "value": "example.com"},
            "wildcard": false,
            "challenges": [
                {
                    "type": "http-01",
                    "status": "pending",
                    "url": "https://acme.test/challenge/1",
                    "token": "gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH"
                }
            ]
        });

        let authorization =
            Authorization::from_json_value(json_value).expect("authorization ayrıştırılmalı");
        assert_eq!(authorization.status(), AuthorizationStatus::Pending);
        let expected_identifier =
            OrderIdentifier::dns("example.com").expect("identifier üretimi başarılı olmalı");
        assert_eq!(authorization.identifier(), &expected_identifier);
        assert_eq!(
            authorization.expires(),
            Some(&datetime!(2024-07-01 12:00:00 UTC))
        );
        assert!(!authorization.wildcard());
        assert_eq!(authorization.challenges().len(), 1);
        let challenge = &authorization.challenges()[0];
        assert_eq!(challenge.kind(), &ChallengeKind::Http01);
        assert_eq!(challenge.status(), ChallengeStatus::Pending);
        assert_eq!(challenge.url().as_str(), "https://acme.test/challenge/1");
        assert_eq!(
            challenge.token(),
            Some("gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH")
        );
        assert!(challenge.validated().is_none());
    }

    #[test]
    fn rejects_invalid_authorization_status() {
        let json_value = json!({
            "status": "mystery",
            "identifier": {"type": "dns", "value": "example.com"},
            "challenges": [
                {
                    "type": "dns-01",
                    "status": "pending",
                    "url": "https://acme.test/challenge/2",
                    "token": "dYx1a0PQWERTyuiopLKJHGFDSAzxcvbnmNBVCXZlk"
                }
            ]
        });

        let err = Authorization::from_json_value(json_value).unwrap_err();
        assert!(matches!(err, AuthorizationError::InvalidStatus { .. }));
        if let AuthorizationError::InvalidStatus { value } = err {
            assert_eq!(value, "mystery");
        } else {
            panic!("beklenmeyen hata: {err:?}");
        }
    }

    #[test]
    fn rejects_token_with_illegal_character() {
        let json_value = json!({
            "status": "pending",
            "identifier": {"type": "dns", "value": "example.com"},
            "challenges": [
                {
                    "type": "http-01",
                    "status": "pending",
                    "url": "https://acme.test/challenge/3",
                    "token": "invalid.token=with+illegal"
                }
            ]
        });

        let err = Authorization::from_json_value(json_value).unwrap_err();
        if let AuthorizationError::Challenge { source, .. } = err {
            assert!(matches!(
                source,
                ChallengeError::InvalidToken { reason }
                    if reason == "token base64url karakterleri dışındakiler içeriyor"
            ));
        } else {
            panic!("beklenmeyen hata: {err:?}");
        }
    }

    #[test]
    fn allows_unknown_challenge_type_without_token() {
        let json_value = json!({
            "status": "valid",
            "identifier": {"type": "dns", "value": "example.org"},
            "challenges": [
                {
                    "type": "custom-01",
                    "status": "valid",
                    "url": "https://acme.test/custom/4"
                }
            ]
        });

        let authorization =
            Authorization::from_json_value(json_value).expect("authorization ayrıştırılmalı");
        assert_eq!(authorization.status(), AuthorizationStatus::Valid);
        let challenge = &authorization.challenges()[0];
        assert!(matches!(challenge.kind(), ChallengeKind::Other(value) if value == "custom-01"));
        assert_eq!(challenge.status(), ChallengeStatus::Valid);
        assert_eq!(challenge.token(), None);
    }
}
