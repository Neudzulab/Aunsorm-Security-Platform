use std::fmt;

use idna::domain_to_ascii;
use percent_encoding::percent_decode_str;
use serde::ser::{Serialize, Serializer};
use serde::Serialize as DeriveSerialize;
use serde_json::Value;
use thiserror::Error;
use url::Url;

/// ACME hesabı için iletişim bilgisi türleri.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountContactKind {
    /// `mailto:` şemasıyla temsil edilen e-posta adresi.
    Email,
    /// `tel:` şemasıyla temsil edilen telefon numarası.
    Telephone,
}

/// ACME hesabı iletişim bilgisi hataları.
#[derive(Debug, Error)]
pub enum AccountContactError {
    /// URI ayrıştırılamadı.
    #[error("ACME account contact URI ayrıştırılamadı: {value}")]
    InvalidUri {
        /// Ayrıştırılmaya çalışılan değer.
        value: String,
        /// Kaynak hata.
        #[source]
        source: url::ParseError,
    },
    /// Desteklenmeyen URI şeması kullanıldı.
    #[error("ACME account contact URI şeması desteklenmiyor: {scheme}")]
    UnsupportedScheme {
        /// Desteklenmeyen şema.
        scheme: String,
    },
    /// E-posta adresi doğrulaması başarısız oldu.
    #[error("ACME account e-posta adresi geçersiz: {value}")]
    InvalidEmail {
        /// Geçersiz e-posta değeri.
        value: String,
    },
    /// Telefon numarası doğrulaması başarısız oldu.
    #[error("ACME account telefon numarası geçersiz: {value}")]
    InvalidTelephone {
        /// Geçersiz telefon numarası değeri.
        value: String,
    },
}

/// ACME hesabı için iletişim bilgisi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountContact {
    uri: String,
    kind: AccountContactKind,
}

impl AccountContact {
    /// Genel URI girdisinden iletişim bilgisi oluşturur.
    ///
    /// # Errors
    ///
    /// URI ayrıştırılamazsa veya desteklenmeyen şemaya sahipse `AccountContactError`
    /// döndürülür.
    pub fn from_uri(value: &str) -> Result<Self, AccountContactError> {
        let trimmed = value.trim();
        let url = Url::parse(trimmed).map_err(|source| AccountContactError::InvalidUri {
            value: trimmed.to_owned(),
            source,
        })?;

        match url.scheme() {
            "mailto" => {
                let decoded = percent_decode_str(url.path()).decode_utf8().map_err(|_| {
                    AccountContactError::InvalidEmail {
                        value: url.path().to_owned(),
                    }
                })?;
                let normalized = normalize_email(decoded.trim())?;
                let mut contact_uri = format!("mailto:{normalized}");
                if let Some(query) = url.query() {
                    contact_uri.push('?');
                    contact_uri.push_str(query);
                }
                if let Some(fragment) = url.fragment() {
                    contact_uri.push('#');
                    contact_uri.push_str(fragment);
                }
                Ok(Self {
                    uri: contact_uri,
                    kind: AccountContactKind::Email,
                })
            }
            "tel" => {
                let decoded = percent_decode_str(url.path()).decode_utf8().map_err(|_| {
                    AccountContactError::InvalidTelephone {
                        value: url.path().to_owned(),
                    }
                })?;
                let normalized = normalize_tel(decoded.trim())?;
                let mut contact_uri = format!("tel:{normalized}");
                if let Some(query) = url.query() {
                    contact_uri.push('?');
                    contact_uri.push_str(query);
                }
                if let Some(fragment) = url.fragment() {
                    contact_uri.push('#');
                    contact_uri.push_str(fragment);
                }
                Ok(Self {
                    uri: contact_uri,
                    kind: AccountContactKind::Telephone,
                })
            }
            other => Err(AccountContactError::UnsupportedScheme {
                scheme: other.to_owned(),
            }),
        }
    }

    /// E-posta adresinden iletişim girdisi oluşturur.
    ///
    /// # Errors
    ///
    /// E-posta değeri doğrulamadan geçmezse `AccountContactError` döndürülür.
    pub fn email(address: &str) -> Result<Self, AccountContactError> {
        let normalized = normalize_email(address.trim())?;
        Ok(Self {
            uri: format!("mailto:{normalized}"),
            kind: AccountContactKind::Email,
        })
    }

    /// Telefon numarasından iletişim girdisi oluşturur.
    ///
    /// # Errors
    ///
    /// Telefon numarası geçersizse `AccountContactError` döndürülür.
    pub fn telephone(number: &str) -> Result<Self, AccountContactError> {
        let normalized = normalize_tel(number.trim())?;
        Ok(Self {
            uri: format!("tel:{normalized}"),
            kind: AccountContactKind::Telephone,
        })
    }

    /// URI değerini döndürür.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// İletişim bilgisinin türünü döndürür.
    #[must_use]
    pub const fn kind(&self) -> AccountContactKind {
        self.kind
    }
}

impl Serialize for AccountContact {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.uri)
    }
}

/// `externalAccountBinding` alanını temsil eden kapsayıcı.
#[derive(Debug, Clone, PartialEq, Eq, DeriveSerialize)]
#[serde(transparent)]
pub struct ExternalAccountBinding {
    value: Value,
}

/// `externalAccountBinding` doğrulama hataları.
#[derive(Debug, Error)]
pub enum ExternalAccountBindingError {
    /// Alan bir JSON objesi değil.
    #[error("ACME externalAccountBinding değeri JSON objesi olmalıdır")]
    NotAnObject,
    /// Zorunlu alan eksik.
    #[error("ACME externalAccountBinding alanı eksik: {field}")]
    MissingField {
        /// Eksik alan adı.
        field: &'static str,
    },
    /// Alan türü beklenen biçimde değil.
    #[error("ACME externalAccountBinding alanı string olmalıdır: {field}")]
    InvalidFieldType {
        /// Hatalı alan adı.
        field: &'static str,
    },
}

impl ExternalAccountBinding {
    /// JSON objesinden `externalAccountBinding` oluşturur.
    ///
    /// # Errors
    ///
    /// Değer beklenen alanları içermiyorsa `ExternalAccountBindingError`
    /// döndürülür.
    pub fn new(value: Value) -> Result<Self, ExternalAccountBindingError> {
        let object = value
            .as_object()
            .ok_or(ExternalAccountBindingError::NotAnObject)?;
        for field in ["protected", "payload", "signature"] {
            match object.get(field) {
                Some(Value::String(_)) => {}
                Some(_) => {
                    return Err(ExternalAccountBindingError::InvalidFieldType { field });
                }
                None => {
                    return Err(ExternalAccountBindingError::MissingField { field });
                }
            }
        }

        Ok(Self { value })
    }

    /// İçteki JSON değerini döndürür.
    #[must_use]
    pub const fn as_json(&self) -> &Value {
        &self.value
    }

    /// İçteki değeri tüketerek döndürür.
    #[must_use]
    pub fn into_json(self) -> Value {
        self.value
    }
}

/// ACME `newAccount` isteği.
#[derive(Debug, Clone, PartialEq, Eq, DeriveSerialize)]
pub struct NewAccountRequest {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    contact: Vec<AccountContact>,
    #[serde(rename = "termsOfServiceAgreed", skip_serializing_if = "is_false")]
    terms_of_service_agreed: bool,
    #[serde(rename = "onlyReturnExisting", skip_serializing_if = "is_false")]
    only_return_existing: bool,
    #[serde(
        rename = "externalAccountBinding",
        skip_serializing_if = "Option::is_none"
    )]
    external_account_binding: Option<ExternalAccountBinding>,
}

impl NewAccountRequest {
    /// Yeni bir builder oluşturur.
    #[must_use]
    pub fn builder() -> NewAccountRequestBuilder {
        NewAccountRequestBuilder::default()
    }

    /// İletişim bilgilerini döndürür.
    #[must_use]
    pub fn contacts(&self) -> &[AccountContact] {
        &self.contact
    }

    /// Kullanıcı şartları kabul etmiş mi?
    #[must_use]
    pub const fn terms_of_service_agreed(&self) -> bool {
        self.terms_of_service_agreed
    }

    /// Sadece mevcut hesabı döndürme bayrağı.
    #[must_use]
    pub const fn only_return_existing(&self) -> bool {
        self.only_return_existing
    }

    /// Harici hesap bağlama verisi varsa döndürür.
    #[must_use]
    pub const fn external_account_binding(&self) -> Option<&ExternalAccountBinding> {
        self.external_account_binding.as_ref()
    }
}

/// `newAccount` isteği oluşturmak için builder.
#[derive(Debug, Default)]
pub struct NewAccountRequestBuilder {
    contact: Vec<AccountContact>,
    terms_of_service_agreed: bool,
    only_return_existing: bool,
    external_account_binding: Option<ExternalAccountBinding>,
}

impl NewAccountRequestBuilder {
    /// Yeni builder oluşturur.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// E-posta veya telefon iletişim girdisi ekler.
    #[must_use]
    pub fn contact(mut self, contact: AccountContact) -> Self {
        self.contact.push(contact);
        self
    }

    /// Birden fazla iletişim girdisi ekler.
    #[must_use]
    pub fn contacts<I>(mut self, contacts: I) -> Self
    where
        I: IntoIterator<Item = AccountContact>,
    {
        self.contact.extend(contacts);
        self
    }

    /// Hizmet şartlarının kabul edildiğini işaretler.
    #[must_use]
    pub const fn agree_to_terms(mut self) -> Self {
        self.terms_of_service_agreed = true;
        self
    }

    /// Hizmet şartları bayrağını manuel olarak ayarlar.
    #[must_use]
    pub const fn terms_of_service_agreed(mut self, agreed: bool) -> Self {
        self.terms_of_service_agreed = agreed;
        self
    }

    /// Sadece mevcut hesabın döndürülmesini talep eder.
    #[must_use]
    pub const fn only_return_existing(mut self, value: bool) -> Self {
        self.only_return_existing = value;
        self
    }

    /// `onlyReturnExisting` bayrağını `true` yapar.
    #[must_use]
    pub const fn query_existing(self) -> Self {
        self.only_return_existing(true)
    }

    /// Harici hesap bağlama bilgisini ayarlar.
    #[must_use]
    pub fn external_account_binding(mut self, binding: ExternalAccountBinding) -> Self {
        self.external_account_binding = Some(binding);
        self
    }

    /// Builder'dan `NewAccountRequest` oluşturur.
    #[must_use]
    pub fn build(self) -> NewAccountRequest {
        NewAccountRequest {
            contact: self.contact,
            terms_of_service_agreed: self.terms_of_service_agreed,
            only_return_existing: self.only_return_existing,
            external_account_binding: self.external_account_binding,
        }
    }
}

fn normalize_email(value: &str) -> Result<String, AccountContactError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AccountContactError::InvalidEmail {
            value: value.to_owned(),
        });
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err(AccountContactError::InvalidEmail {
            value: trimmed.to_owned(),
        });
    }

    if trimmed.chars().filter(|&c| c == '@').count() != 1 {
        return Err(AccountContactError::InvalidEmail {
            value: trimmed.to_owned(),
        });
    }

    let (local, domain) =
        trimmed
            .rsplit_once('@')
            .ok_or_else(|| AccountContactError::InvalidEmail {
                value: trimmed.to_owned(),
            })?;

    if local.is_empty() || domain.is_empty() || local.contains('@') {
        return Err(AccountContactError::InvalidEmail {
            value: trimmed.to_owned(),
        });
    }

    if !is_valid_local_part(local) {
        return Err(AccountContactError::InvalidEmail {
            value: trimmed.to_owned(),
        });
    }

    let ascii_domain = domain_to_ascii(domain).map_err(|_| AccountContactError::InvalidEmail {
        value: trimmed.to_owned(),
    })?;

    Ok(format!("{local}@{ascii_domain}"))
}

fn normalize_tel(value: &str) -> Result<String, AccountContactError> {
    if value.is_empty() {
        return Err(AccountContactError::InvalidTelephone {
            value: value.to_owned(),
        });
    }

    let mut has_digit = false;
    for (index, ch) in value.chars().enumerate() {
        if ch.is_ascii_digit() {
            has_digit = true;
            continue;
        }

        if ch == '+' {
            if index != 0 {
                return Err(AccountContactError::InvalidTelephone {
                    value: value.to_owned(),
                });
            }
            continue;
        }

        if ch.is_ascii_alphabetic() || matches!(ch, '-' | '.' | '(' | ')' | ';' | '=' | ',') {
            continue;
        }

        return Err(AccountContactError::InvalidTelephone {
            value: value.to_owned(),
        });
    }

    if !has_digit {
        return Err(AccountContactError::InvalidTelephone {
            value: value.to_owned(),
        });
    }

    Ok(value.to_owned())
}

fn is_valid_local_part(value: &str) -> bool {
    if value.starts_with('.') || value.ends_with('.') {
        return false;
    }

    let mut previous_was_dot = false;
    for ch in value.chars() {
        if ch == '.' {
            if previous_was_dot {
                return false;
            }
            previous_was_dot = true;
            continue;
        }

        previous_was_dot = false;
        if !(ch.is_ascii_alphanumeric()
            || matches!(
                ch,
                '!' | '#'
                    | '$'
                    | '%'
                    | '&'
                    | '\''
                    | '*'
                    | '+'
                    | '-'
                    | '/'
                    | '='
                    | '?'
                    | '^'
                    | '_'
                    | '`'
                    | '{'
                    | '|'
                    | '}'
                    | '~'
            ))
        {
            return false;
        }
    }

    !value.is_empty()
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

impl fmt::Display for AccountContact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.uri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serde_json::json;

    #[test]
    fn email_contact_normalizes_domain() {
        let contact = AccountContact::email("Admin@Exämple.com").expect("geçerli e-posta");
        assert_eq!(contact.kind(), AccountContactKind::Email);
        assert_eq!(contact.uri(), "mailto:Admin@xn--exmple-cua.com");
    }

    #[test]
    fn email_contact_rejects_invalid() {
        let err = AccountContact::email("not-an-email").unwrap_err();
        assert!(matches!(err, AccountContactError::InvalidEmail { .. }));
    }

    #[test]
    fn telephone_contact_accepts_extension() {
        let contact = AccountContact::telephone("+1-555-0100;ext=200").expect("geçerli telefon");
        assert_eq!(contact.kind(), AccountContactKind::Telephone);
        assert_eq!(contact.uri(), "tel:+1-555-0100;ext=200");
    }

    #[test]
    fn telephone_contact_rejects_spaces() {
        let err = AccountContact::telephone("+1 555 0100").unwrap_err();
        assert!(matches!(err, AccountContactError::InvalidTelephone { .. }));
    }

    #[test]
    fn from_uri_preserves_query_parameters() {
        let contact =
            AccountContact::from_uri("mailto:admin@example.com?subject=Hi").expect("geçerli uri");
        assert_eq!(contact.uri(), "mailto:admin@example.com?subject=Hi");
        assert_eq!(contact.kind(), AccountContactKind::Email);
    }

    #[test]
    fn from_uri_rejects_unsupported_scheme() {
        let err = AccountContact::from_uri("https://example.com").unwrap_err();
        assert!(matches!(err, AccountContactError::UnsupportedScheme { .. }));
    }

    #[test]
    fn external_account_binding_requires_fields() {
        let value = json!({
            "protected": "abc",
            "payload": "def",
            "signature": "ghi"
        });
        let binding = ExternalAccountBinding::new(value.clone()).expect("geçerli binding");
        assert_eq!(binding.as_json(), &value);

        let err = ExternalAccountBinding::new(json!({"protected": 1})).unwrap_err();
        assert!(matches!(
            err,
            ExternalAccountBindingError::InvalidFieldType { .. }
        ));
    }

    #[test]
    fn new_account_request_serializes_flags() {
        let contact = AccountContact::email("admin@example.com").expect("geçerli e-posta");
        let binding = ExternalAccountBinding::new(json!({
            "protected": "hdr",
            "payload": "body",
            "signature": "sig"
        }))
        .expect("binding");

        let request = NewAccountRequest::builder()
            .contact(contact)
            .agree_to_terms()
            .query_existing()
            .external_account_binding(binding.clone())
            .build();

        let value = serde_json::to_value(&request).expect("serileştirme");
        assert_eq!(
            value,
            json!({
                "contact": ["mailto:admin@example.com"],
                "termsOfServiceAgreed": true,
                "onlyReturnExisting": true,
                "externalAccountBinding": binding.as_json()
            })
        );
    }

    #[test]
    fn new_account_request_skips_defaults() {
        let request = NewAccountRequest::builder().build();
        let value = serde_json::to_value(&request).expect("serileştirme");
        assert_eq!(value, json!({}));
    }
}
