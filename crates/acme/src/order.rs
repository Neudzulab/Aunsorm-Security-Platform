use std::borrow::Cow;
use std::fmt;
use std::net::IpAddr;

use serde::ser::{Serialize, SerializeStruct, Serializer};
use serde::Serialize as DeriveSerialize;
use thiserror::Error;
use time::OffsetDateTime;

/// ACME order identifier türleri.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierKind {
    /// DNS tabanlı identifier.
    Dns,
    /// IP adresi tabanlı identifier.
    Ip,
}

/// ACME order identifier değerlerinin doğrulama hataları.
#[derive(Debug, Error)]
pub enum OrderIdentifierError {
    /// DNS identifier değeri boş bırakıldı.
    #[error("ACME DNS identifier değeri boş olamaz")]
    EmptyDns,
    /// DNS identifier değeri geçersiz karakter içeriyor veya hatalı biçimde.
    #[error("ACME DNS identifier değeri geçersiz: {value}")]
    InvalidDns { value: String },
    /// IP identifier değeri ayrıştırılamadı.
    #[error("ACME IP identifier değeri ayrıştırılamadı: {source}")]
    InvalidIp {
        #[from]
        source: std::net::AddrParseError,
    },
}

/// ACME order identifier değeri.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderIdentifier {
    /// DNS identifier.
    Dns(String),
    /// IP adresi identifier.
    Ip(IpAddr),
}

impl OrderIdentifier {
    /// DNS identifier oluşturur ve doğrular.
    ///
    /// # Errors
    ///
    /// DNS değeri boşsa veya geçersiz karakter içeriyorsa `OrderIdentifierError`
    /// döndürülür.
    pub fn dns(value: &str) -> Result<Self, OrderIdentifierError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(OrderIdentifierError::EmptyDns);
        }

        let without_trailing_dot = trimmed.trim_end_matches('.');
        if without_trailing_dot.is_empty() {
            return Err(OrderIdentifierError::EmptyDns);
        }

        let normalized = without_trailing_dot.to_ascii_lowercase();
        if normalized.len() > 253 {
            return Err(OrderIdentifierError::InvalidDns {
                value: trimmed.to_owned(),
            });
        }

        for (index, label) in normalized.split('.').enumerate() {
            if label.is_empty() {
                return Err(OrderIdentifierError::InvalidDns {
                    value: trimmed.to_owned(),
                });
            }

            if label == "*" {
                if index != 0 {
                    return Err(OrderIdentifierError::InvalidDns {
                        value: trimmed.to_owned(),
                    });
                }
                continue;
            }

            if label.len() > 63 {
                return Err(OrderIdentifierError::InvalidDns {
                    value: trimmed.to_owned(),
                });
            }

            if label.starts_with('-') || label.ends_with('-') {
                return Err(OrderIdentifierError::InvalidDns {
                    value: trimmed.to_owned(),
                });
            }

            if label
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_')))
            {
                return Err(OrderIdentifierError::InvalidDns {
                    value: trimmed.to_owned(),
                });
            }
        }

        Ok(Self::Dns(normalized))
    }

    /// IP identifier oluşturur ve doğrular.
    ///
    /// # Errors
    ///
    /// IP değeri ayrıştırılamadığında `OrderIdentifierError::InvalidIp` döner.
    pub fn ip(value: &str) -> Result<Self, OrderIdentifierError> {
        let addr: IpAddr = value.trim().parse()?;
        Ok(Self::Ip(addr))
    }

    /// Identifier türünü döndürür.
    #[must_use]
    pub const fn kind(&self) -> IdentifierKind {
        match self {
            Self::Dns(_) => IdentifierKind::Dns,
            Self::Ip(_) => IdentifierKind::Ip,
        }
    }

    /// Identifier değerini metin olarak döndürür.
    #[must_use]
    pub fn value(&self) -> Cow<'_, str> {
        match self {
            Self::Dns(value) => Cow::Borrowed(value.as_str()),
            Self::Ip(addr) => Cow::Owned(addr.to_string()),
        }
    }
}

impl Serialize for OrderIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("OrderIdentifier", 2)?;
        state.serialize_field(
            "type",
            match self.kind() {
                IdentifierKind::Dns => "dns",
                IdentifierKind::Ip => "ip",
            },
        )?;
        state.serialize_field("value", &self.value())?;
        state.end()
    }
}

/// `newOrder` isteği oluştururken kullanılacak hata türleri.
#[derive(Debug, Error)]
pub enum NewOrderError {
    /// Hiç identifier sağlanmadı.
    #[error("ACME newOrder isteği en az bir identifier içermelidir")]
    MissingIdentifier,
    /// Identifier üretimi sırasında hata oluştu.
    #[error(transparent)]
    Identifier(#[from] OrderIdentifierError),
    /// `notAfter` değeri `notBefore` tarihinden önce.
    #[error("ACME newOrder zaman aralığı geçersiz: notAfter, notBefore değerinden önce")]
    InvalidTimeWindow,
}

/// ACME `newOrder` isteği.
#[derive(Debug, Clone, PartialEq, Eq, DeriveSerialize)]
pub struct NewOrderRequest {
    identifiers: Vec<OrderIdentifier>,
    #[serde(
        rename = "notBefore",
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    not_before: Option<OffsetDateTime>,
    #[serde(
        rename = "notAfter",
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    not_after: Option<OffsetDateTime>,
}

impl NewOrderRequest {
    /// Identifier listesinden yeni bir order isteği oluşturur.
    ///
    /// # Errors
    ///
    /// Liste boşsa `NewOrderError::MissingIdentifier` döndürür.
    pub fn new(identifiers: Vec<OrderIdentifier>) -> Result<Self, NewOrderError> {
        if identifiers.is_empty() {
            return Err(NewOrderError::MissingIdentifier);
        }
        Ok(Self {
            identifiers,
            not_before: None,
            not_after: None,
        })
    }

    /// DNS isimleri için order isteği üretir.
    ///
    /// # Errors
    ///
    /// Herhangi bir domain geçersizse veya liste boşsa `NewOrderError`
    /// döndürülür.
    pub fn for_dns_names<I, S>(names: I) -> Result<Self, NewOrderError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let identifiers = names
            .into_iter()
            .map(|name| OrderIdentifier::dns(name.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(identifiers)
    }

    /// IP adresleri için order isteği üretir.
    ///
    /// # Errors
    ///
    /// IP listesi boşsa veya geçersiz adres içeriyorsa hata döndürür.
    pub fn for_ip_addresses<I, S>(addresses: I) -> Result<Self, NewOrderError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let identifiers = addresses
            .into_iter()
            .map(|value| OrderIdentifier::ip(value.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(identifiers)
    }

    /// Builder yardımıyla `newOrder` isteği oluşturur.
    #[must_use]
    pub fn builder() -> NewOrderRequestBuilder {
        NewOrderRequestBuilder::default()
    }

    /// Identifier listesini döndürür.
    #[must_use]
    pub fn identifiers(&self) -> &[OrderIdentifier] {
        &self.identifiers
    }

    /// `notBefore` değerini döndürür.
    #[must_use]
    pub const fn not_before(&self) -> Option<&OffsetDateTime> {
        self.not_before.as_ref()
    }

    /// `notAfter` değerini döndürür.
    #[must_use]
    pub const fn not_after(&self) -> Option<&OffsetDateTime> {
        self.not_after.as_ref()
    }
}

impl fmt::Display for NewOrderRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ACME newOrder ({} identifier)", self.identifiers.len())
    }
}

/// `newOrder` isteği üretmek için builder.
#[derive(Debug, Default)]
pub struct NewOrderRequestBuilder {
    identifiers: Vec<OrderIdentifier>,
    not_before: Option<OffsetDateTime>,
    not_after: Option<OffsetDateTime>,
}

impl NewOrderRequestBuilder {
    /// Yeni bir builder oluşturur.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Identifier ekler.
    #[must_use]
    pub fn identifier(mut self, identifier: OrderIdentifier) -> Self {
        self.identifiers.push(identifier);
        self
    }

    /// Birden fazla identifier ekler.
    #[must_use]
    pub fn identifiers<I>(mut self, identifiers: I) -> Self
    where
        I: IntoIterator<Item = OrderIdentifier>,
    {
        self.identifiers.extend(identifiers);
        self
    }

    /// `notBefore` değerini ayarlar.
    #[must_use]
    pub const fn not_before(mut self, value: OffsetDateTime) -> Self {
        self.not_before = Some(value);
        self
    }

    /// `notAfter` değerini ayarlar.
    #[must_use]
    pub const fn not_after(mut self, value: OffsetDateTime) -> Self {
        self.not_after = Some(value);
        self
    }

    /// Builder'dan order isteği oluşturur.
    ///
    /// # Errors
    ///
    /// Hiç identifier eklenmediyse veya zaman aralığı geçersizse hata döner.
    pub fn build(self) -> Result<NewOrderRequest, NewOrderError> {
        if self.identifiers.is_empty() {
            return Err(NewOrderError::MissingIdentifier);
        }

        if let (Some(not_before), Some(not_after)) = (&self.not_before, &self.not_after) {
            if not_after < not_before {
                return Err(NewOrderError::InvalidTimeWindow);
            }
        }

        Ok(NewOrderRequest {
            identifiers: self.identifiers,
            not_before: self.not_before,
            not_after: self.not_after,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use time::macros::datetime;

    #[test]
    fn dns_identifier_validation() {
        let identifier = OrderIdentifier::dns("example.com").expect("geçerli dns");
        assert_eq!(identifier.kind(), IdentifierKind::Dns);
        assert_eq!(identifier.value(), Cow::Borrowed("example.com"));
    }

    #[test]
    fn dns_identifier_rejects_invalid_label() {
        let err = OrderIdentifier::dns("exa mple.com").unwrap_err();
        assert!(matches!(err, OrderIdentifierError::InvalidDns { .. }));
    }

    #[test]
    fn dns_identifier_allows_wildcard_prefix() {
        let identifier = OrderIdentifier::dns("*.example.com").expect("wildcard kabul edilmeli");
        assert_eq!(identifier.value(), Cow::Borrowed("*.example.com"));
    }

    #[test]
    fn ip_identifier_parses_ipv6() {
        let identifier = OrderIdentifier::ip("2001:db8::1").expect("geçerli ipv6");
        assert_eq!(identifier.kind(), IdentifierKind::Ip);
        let value = identifier.value();
        assert!(matches!(value, Cow::Owned(_)));
        assert_eq!(value.as_ref(), "2001:db8::1");
    }

    #[test]
    fn new_order_request_serializes() {
        let not_before = datetime!(2024-01-01 00:00:00 UTC);
        let not_after = datetime!(2024-12-31 23:59:59 UTC);
        let request = NewOrderRequest::builder()
            .identifier(OrderIdentifier::dns("example.com").unwrap())
            .identifier(OrderIdentifier::dns("_acme-challenge.example.com").unwrap())
            .not_before(not_before)
            .not_after(not_after)
            .build()
            .expect("order oluşturulmalı");

        let json_value = serde_json::to_value(&request).expect("json serileşmeli");
        assert_eq!(
            json_value,
            json!({
                "identifiers": [
                    {"type": "dns", "value": "example.com"},
                    {"type": "dns", "value": "_acme-challenge.example.com"}
                ],
                "notBefore": "2024-01-01T00:00:00Z",
                "notAfter": "2024-12-31T23:59:59Z"
            })
        );
    }

    #[test]
    fn builder_rejects_empty_identifiers() {
        let err = NewOrderRequest::builder().build().unwrap_err();
        assert!(matches!(err, NewOrderError::MissingIdentifier));
    }

    #[test]
    fn builder_rejects_invalid_time_window() {
        let err = NewOrderRequest::builder()
            .identifier(OrderIdentifier::dns("example.com").unwrap())
            .not_before(datetime!(2024-05-01 12:00:00 UTC))
            .not_after(datetime!(2024-04-01 12:00:00 UTC))
            .build()
            .unwrap_err();
        assert!(matches!(err, NewOrderError::InvalidTimeWindow));
    }

    #[test]
    fn for_dns_names_produces_identifiers() {
        let request = NewOrderRequest::for_dns_names(["example.com", "www.example.com"])
            .expect("order üretimi");
        assert_eq!(request.identifiers().len(), 2);
        assert_eq!(
            request.identifiers()[0].value(),
            Cow::Borrowed("example.com")
        );
    }

    #[test]
    fn for_ip_addresses_propagates_error() {
        let err = NewOrderRequest::for_ip_addresses(["not-an-ip"]).unwrap_err();
        assert!(matches!(
            err,
            NewOrderError::Identifier(OrderIdentifierError::InvalidIp { .. })
        ));
    }
}
