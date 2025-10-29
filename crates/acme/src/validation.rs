//! Domain validation helpers for ACME challenges.

#![allow(clippy::module_name_repetitions)]

pub mod dns01;
pub mod http01;

use std::fmt;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{pkcs8::EncodePrivateKey, SigningKey};
use rand_core::{CryptoRng, RngCore};
use rcgen::{
    Certificate, CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair,
    PKCS_ED25519,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::authorization::{
    validate_token, Authorization, Challenge, ChallengeError, ChallengeKind,
};
use crate::order::OrderIdentifier;
use crate::rng::AunsormNativeRng;

/// ACME challenge lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChallengeState {
    /// Challenge henüz yayınlanmadı.
    Pending,
    /// Challenge istemciye yayınlandı.
    Published,
    /// Challenge doğrulamaya hazır veya doğrulandı.
    Verified,
    /// Challenge içerikleri geri çağrıldı.
    Revoked,
    /// Challenge doğrulaması başarısız oldu.
    Invalid,
}

/// Errors that can occur while preparing or validating an HTTP-01 challenge.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Http01ValidationError {
    /// The provided challenge is not an HTTP-01 challenge.
    #[error("Challenge HTTP-01 türünde değil")]
    NotHttp01,
    /// The challenge does not contain a token value.
    #[error("HTTP-01 challenge token değeri eksik")]
    MissingToken,
    /// The challenge token violates RFC 8555 constraints.
    #[error("HTTP-01 challenge token değeri geçersiz: {reason}")]
    InvalidToken {
        /// Why the token is considered invalid.
        reason: &'static str,
    },
    /// The supplied account thumbprint is empty.
    #[error("HTTP-01 challenge için hesap thumbprint değeri boş olamaz")]
    EmptyThumbprint,
    /// The supplied account thumbprint cannot be decoded as base64url data.
    #[error("HTTP-01 challenge thumbprint değeri geçersiz: {reason}")]
    InvalidThumbprint {
        /// Why the thumbprint failed validation.
        reason: &'static str,
    },
    /// The returned body does not match the expected key authorization value.
    #[error("HTTP-01 challenge yanıtı key-authorization değeriyle eşleşmiyor")]
    BodyMismatch {
        /// Expected key-authorization value.
        expected: String,
        /// Received body after whitespace normalisation.
        received: String,
    },
}

/// Prepared key-authorization data for a single HTTP-01 challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http01KeyAuthorization {
    token: String,
    thumbprint: String,
    resource_path: String,
    key_authorization: String,
}

impl Http01KeyAuthorization {
    /// Builds a key-authorization value from a raw challenge token and account thumbprint.
    ///
    /// # Errors
    ///
    /// Returns [`Http01ValidationError`] when the token does not comply with RFC 8555 rules
    /// or when the thumbprint cannot be decoded as a SHA-256 hash.
    pub fn new(token: &str, account_thumbprint: &str) -> Result<Self, Http01ValidationError> {
        match validate_token(token) {
            Ok(()) => {}
            Err(ChallengeError::InvalidToken { reason }) => {
                return Err(Http01ValidationError::InvalidToken { reason });
            }
            Err(_) => {
                return Err(Http01ValidationError::InvalidToken {
                    reason: "token doğrulaması başarısız",
                });
            }
        }
        let trimmed_thumbprint = account_thumbprint.trim();
        if trimmed_thumbprint.is_empty() {
            return Err(Http01ValidationError::EmptyThumbprint);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(trimmed_thumbprint.as_bytes())
            .map_err(|_| Http01ValidationError::InvalidThumbprint {
                reason: "thumbprint base64url formatında olmalıdır",
            })?;
        if decoded.len() != 32 {
            return Err(Http01ValidationError::InvalidThumbprint {
                reason: "thumbprint SHA-256 (32 bayt) uzunluğunda olmalıdır",
            });
        }

        let key_authorization = format!("{token}.{trimmed_thumbprint}");
        let resource_path = format!("/.well-known/acme-challenge/{token}");

        Ok(Self {
            token: token.to_owned(),
            thumbprint: trimmed_thumbprint.to_owned(),
            resource_path,
            key_authorization,
        })
    }

    /// Creates an HTTP-01 context from a parsed ACME challenge.
    ///
    /// # Errors
    ///
    /// Returns [`Http01ValidationError`] if the challenge is not HTTP-01, does not include a token,
    /// or fails token/thumbprint validation.
    pub fn from_challenge(
        challenge: &Challenge,
        account_thumbprint: &str,
    ) -> Result<Self, Http01ValidationError> {
        if !matches!(challenge.kind(), ChallengeKind::Http01) {
            return Err(Http01ValidationError::NotHttp01);
        }
        let token = challenge
            .token()
            .ok_or(Http01ValidationError::MissingToken)?;
        Self::new(token, account_thumbprint)
    }

    /// Returns the raw challenge token.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn token(&self) -> &str {
        self.token.as_str()
    }

    /// Returns the account thumbprint associated with this challenge.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn thumbprint(&self) -> &str {
        self.thumbprint.as_str()
    }

    /// Returns the HTTP resource path that must be served for the challenge.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn resource_path(&self) -> &str {
        self.resource_path.as_str()
    }

    /// Returns the key-authorization value expected in the HTTP response body.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn key_authorization(&self) -> &str {
        self.key_authorization.as_str()
    }

    /// Verifies that an HTTP response body matches the key-authorization string.
    ///
    /// Trailing whitespace (spaces, tabs, CR and LF characters) is ignored to allow
    /// compatibility with simple file deployments that append a newline.
    ///
    /// # Errors
    ///
    /// Returns [`Http01ValidationError::BodyMismatch`] if the body does not match the expected
    /// key-authorization string after normalisation.
    pub fn verify_body(&self, body: &str) -> Result<(), Http01ValidationError> {
        let normalised = trim_trailing_http_whitespace(body);
        if normalised == self.key_authorization {
            Ok(())
        } else {
            Err(Http01ValidationError::BodyMismatch {
                expected: self.key_authorization.clone(),
                received: normalised.to_owned(),
            })
        }
    }
}

/// Errors that can occur while preparing DNS-01 validation records.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Dns01ValidationError {
    /// The provided challenge is not a DNS-01 challenge.
    #[error("Challenge DNS-01 türünde değil")]
    NotDns01,
    /// The challenge does not contain a token value.
    #[error("DNS-01 challenge token değeri eksik")]
    MissingToken,
    /// DNS-01 requires a DNS identifier on the authorization object.
    #[error("DNS-01 challenge yalnızca DNS identifier ile kullanılabilir")]
    UnsupportedIdentifier,
    /// Underlying key-authorization preparation failed.
    #[error("DNS-01 key-authorization doğrulaması başarısız: {source}")]
    KeyAuthorization {
        /// Source HTTP-01 style validation error.
        #[from]
        source: Http01ValidationError,
    },
    /// DNS sorgusu beklenen TXT kaydını içermiyor.
    #[error("DNS-01 TXT kaydı bulunamadı veya farklı değer döndü")]
    MissingRecord,
    /// Dönen TXT kaydı beklenen değerle eşleşmedi.
    #[error(
        "DNS-01 TXT kaydı beklenen değerle eşleşmedi. Beklenen: {expected}, alınan: {received:?}"
    )]
    RecordMismatch {
        /// Beklenen TXT değeri.
        expected: String,
        /// Sorgu sonucunda elde edilen değerler.
        received: Vec<String>,
    },
}

/// Prepared TXT record information for satisfying a DNS-01 challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dns01TxtRecord {
    name: String,
    value: String,
}

impl Dns01TxtRecord {
    /// Builds a TXT record from a raw challenge token, identifier and account thumbprint.
    ///
    /// # Errors
    ///
    /// Returns [`Dns01ValidationError`] when the identifier is not DNS based or when the
    /// underlying HTTP-01 key-authorization checks fail.
    pub fn new(
        token: &str,
        identifier: &OrderIdentifier,
        account_thumbprint: &str,
    ) -> Result<Self, Dns01ValidationError> {
        let dns_identifier = match identifier {
            OrderIdentifier::Dns(value) => value.as_str(),
            OrderIdentifier::Ip(_) => return Err(Dns01ValidationError::UnsupportedIdentifier),
        };
        let key_authorization = Http01KeyAuthorization::new(token, account_thumbprint)?;
        let digest = Sha256::digest(key_authorization.key_authorization().as_bytes());
        let record_value = URL_SAFE_NO_PAD.encode(digest);
        let record_name = format!(
            "_acme-challenge.{}",
            dns_identifier.strip_prefix("*.").unwrap_or(dns_identifier)
        );
        Ok(Self {
            name: record_name,
            value: record_value,
        })
    }

    /// Creates a TXT record from a parsed authorization and challenge pair.
    ///
    /// # Errors
    ///
    /// Returns [`Dns01ValidationError`] when the challenge is not DNS-01, when it lacks a
    /// token, the identifier is not DNS based or underlying validation fails.
    pub fn from_authorization(
        authorization: &Authorization,
        challenge: &Challenge,
        account_thumbprint: &str,
    ) -> Result<Self, Dns01ValidationError> {
        if !matches!(challenge.kind(), ChallengeKind::Dns01) {
            return Err(Dns01ValidationError::NotDns01);
        }
        let token = challenge
            .token()
            .ok_or(Dns01ValidationError::MissingToken)?;
        Self::new(token, authorization.identifier(), account_thumbprint)
    }

    /// Returns the FQDN that must contain the TXT record.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns the TXT record value required by the DNS-01 challenge.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn value(&self) -> &str {
        self.value.as_str()
    }
}

/// TLS-ALPN-01 doğrulama verilerini hazırlarken oluşabilecek hatalar.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TlsAlpnValidationError {
    /// Sağlanan challenge TLS-ALPN-01 türünde değil.
    #[error("Challenge TLS-ALPN-01 türünde değil")]
    NotTlsAlpn01,
    /// Challenge token değeri eksik.
    #[error("TLS-ALPN challenge token değeri eksik")]
    MissingToken,
    /// TLS-ALPN yalnızca DNS tabanlı identifier'larla kullanılabilir.
    #[error("TLS-ALPN challenge yalnızca DNS identifier ile kullanılabilir")]
    UnsupportedIdentifier,
    /// HTTP-01 key-authorization doğrulaması başarısız oldu.
    #[error("TLS-ALPN key-authorization doğrulaması başarısız: {source}")]
    KeyAuthorization {
        /// Kaynak doğrulama hatası.
        #[from]
        source: Http01ValidationError,
    },
}

/// TLS-ALPN-01 challenge verilerini temsil eder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsAlpnChallenge {
    domain: String,
    key_authorization: Http01KeyAuthorization,
    digest: [u8; 32],
}

impl TlsAlpnChallenge {
    /// ACME TLS-ALPN-01 için kullanılacak ALPN protokol dizesi.
    pub const ALPN_PROTOCOL: &'static str = "acme-tls/1";

    /// Challenge token'ı ve identifier'dan TLS-ALPN bağlamı oluşturur.
    ///
    /// # Errors
    ///
    /// DNS dışı identifier'larda veya key-authorization doğrulaması başarısız
    /// olduğunda [`TlsAlpnValidationError`] döndürür.
    pub fn new(
        token: &str,
        identifier: &OrderIdentifier,
        account_thumbprint: &str,
    ) -> Result<Self, TlsAlpnValidationError> {
        let domain = match identifier {
            OrderIdentifier::Dns(value) => value.strip_prefix("*.").unwrap_or(value).to_owned(),
            OrderIdentifier::Ip(_) => return Err(TlsAlpnValidationError::UnsupportedIdentifier),
        };

        let key_authorization = Http01KeyAuthorization::new(token, account_thumbprint)?;
        let digest = Sha256::digest(key_authorization.key_authorization().as_bytes());
        let mut digest_bytes = [0u8; 32];
        digest_bytes.copy_from_slice(&digest);

        Ok(Self {
            domain,
            key_authorization,
            digest: digest_bytes,
        })
    }

    /// Authorization/challenge çiftinden TLS-ALPN bağlamı oluşturur.
    ///
    /// # Errors
    ///
    /// Challenge TLS-ALPN-01 türünde değilse, token alanı eksikse veya
    /// doğrulama başarısız olursa [`TlsAlpnValidationError`] döndürür.
    pub fn from_authorization(
        authorization: &Authorization,
        challenge: &Challenge,
        account_thumbprint: &str,
    ) -> Result<Self, TlsAlpnValidationError> {
        if !matches!(challenge.kind(), ChallengeKind::TlsAlpn01) {
            return Err(TlsAlpnValidationError::NotTlsAlpn01);
        }
        let token = challenge
            .token()
            .ok_or(TlsAlpnValidationError::MissingToken)?;
        Self::new(token, authorization.identifier(), account_thumbprint)
    }

    /// DNS tabanlı domain değerini döndürür.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn domain(&self) -> &str {
        self.domain.as_str()
    }

    /// Challenge key-authorization değerini döndürür.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn key_authorization(&self) -> &str {
        self.key_authorization.key_authorization()
    }

    /// Key-authorization SHA-256 özetini döndürür.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// TLS-ALPN sertifikasını deterministik bir RNG ile üretir.
    ///
    /// # Errors
    ///
    /// Sertifika oluşturulurken hata oluşursa [`TlsAlpnCertificateError`]
    /// döner.
    pub fn create_certificate_with_rng<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<TlsAlpnCertificate, TlsAlpnCertificateError> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let key_doc = signing_key
            .to_pkcs8_der()
            .map_err(|err| TlsAlpnCertificateError::KeyEncoding(err.to_string()))?;
        let private_key_der = Zeroizing::new(key_doc.as_bytes().to_vec());
        let key_pair = KeyPair::from_der(private_key_der.as_slice())
            .map_err(|err| TlsAlpnCertificateError::Certificate(err.to_string()))?;

        let mut params = CertificateParams::new(vec![self.domain.clone()]);
        params.alg = &PKCS_ED25519;
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, self.domain.clone());
        params
            .custom_extensions
            .push(CustomExtension::new_acme_identifier(&self.digest));
        params.key_pair = Some(key_pair);

        let certificate = Certificate::from_params(params)
            .map_err(|err| TlsAlpnCertificateError::Certificate(err.to_string()))?;
        let certificate_der = certificate
            .serialize_der()
            .map_err(|err| TlsAlpnCertificateError::Certificate(err.to_string()))?;

        Ok(TlsAlpnCertificate {
            domain: self.domain.clone(),
            certificate_der,
            private_key_der,
            digest: self.digest,
        })
    }

    /// TLS-ALPN sertifikasını Aunsorm native RNG ile üretir.
    ///
    /// # Errors
    ///
    /// Sertifika oluşturulurken hata oluşursa [`TlsAlpnCertificateError`]
    /// döner.
    pub fn create_certificate(&self) -> Result<TlsAlpnCertificate, TlsAlpnCertificateError> {
        let mut rng = AunsormNativeRng::new();
        self.create_certificate_with_rng(&mut rng)
    }
}

/// TLS-ALPN sertifikasını ve ilişkili materyali temsil eder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsAlpnCertificate {
    domain: String,
    certificate_der: Vec<u8>,
    private_key_der: Zeroizing<Vec<u8>>,
    digest: [u8; 32],
}

impl TlsAlpnCertificate {
    /// ACME TLS-ALPN-01 için kullanılacak ALPN protokol dizesi.
    pub const ALPN_PROTOCOL: &'static str = TlsAlpnChallenge::ALPN_PROTOCOL;

    /// Sertifikanın hedef domain'ini döndürür.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn domain(&self) -> &str {
        self.domain.as_str()
    }

    /// Sertifikanın DER kodlu halini döndürür.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn certificate_der(&self) -> &[u8] {
        self.certificate_der.as_slice()
    }

    /// Özel anahtarın PKCS#8 DER kodunu döndürür.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn private_key_der(&self) -> &[u8] {
        self.private_key_der.as_slice()
    }

    /// Key-authorization SHA-256 özetini döndürür.
    #[must_use]
    pub const fn key_authorization_digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Sertifikayı PEM formatında döndürür.
    #[must_use]
    pub fn certificate_pem(&self) -> String {
        encode_pem("CERTIFICATE", self.certificate_der())
    }

    /// Özel anahtarı PEM formatında döndürür.
    #[must_use]
    pub fn private_key_pem(&self) -> String {
        encode_pem("PRIVATE KEY", self.private_key_der())
    }

    /// ALPN protokol dizesini döndürür.
    #[must_use]
    pub const fn alpn_protocol(&self) -> &'static str {
        Self::ALPN_PROTOCOL
    }
}

/// TLS-ALPN sertifikası üretilirken oluşabilecek hatalar.
#[derive(Debug, Error)]
pub enum TlsAlpnCertificateError {
    /// Girdi doğrulaması başarısız oldu.
    #[error("TLS-ALPN doğrulaması başarısız: {0}")]
    Validation(#[from] TlsAlpnValidationError),
    /// Ed25519 anahtarı PKCS#8 olarak kodlanamadı.
    #[error("Ed25519 anahtarı PKCS#8 olarak kodlanamadı: {0}")]
    KeyEncoding(String),
    /// Sertifika oluşturma sırasında hata oluştu.
    #[error("TLS-ALPN sertifikası oluşturulamadı: {0}")]
    Certificate(String),
}

fn trim_trailing_http_whitespace(input: &str) -> &str {
    let without_newlines = input.trim_end_matches(['\n', '\r']);
    without_newlines.trim_end_matches([' ', '\t'])
}

fn encode_pem(label: &str, der: &[u8]) -> String {
    let mut pem = String::new();
    pem.push_str("-----BEGIN ");
    pem.push_str(label);
    pem.push_str("-----\n");
    let encoded = STANDARD.encode(der);
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(chunk));
        pem.push('\n');
    }
    pem.push_str("-----END ");
    pem.push_str(label);
    pem.push_str("-----\n");
    pem
}

impl fmt::Display for Http01KeyAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key_authorization())
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::authorization::{Authorization, Challenge};
    use crate::order::OrderIdentifier;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use serde_json::json;
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::oid_registry::Oid;

    fn sample_challenge(token: &str) -> Challenge {
        let authorization = Authorization::from_json_value(json!({
            "status": "pending",
            "identifier": {"type": "dns", "value": "example.com"},
            "challenges": [
                {
                    "type": "http-01",
                    "status": "pending",
                    "url": "https://acme.invalid/challenge/1",
                    "token": token,
                }
            ]
        }))
        .expect("authorization ayrıştırılmalı");
        authorization
            .challenges()
            .first()
            .expect("challenge mevcut olmalı")
            .clone()
    }

    #[test]
    fn builds_key_authorization_from_token_and_thumbprint() {
        let context = Http01KeyAuthorization::new(
            "gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH",
            "ytxINsp8lvQ1mX8kGqCFyT9OQy2M7o1uz7NErHOwhwU",
        )
        .expect("geçerli context oluşturulmalı");
        assert_eq!(
            context.resource_path(),
            "/.well-known/acme-challenge/gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH"
        );
        assert_eq!(
            context.key_authorization(),
            "gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH.ytxINsp8lvQ1mX8kGqCFyT9OQy2M7o1uz7NErHOwhwU"
        );
    }

    #[test]
    fn builds_context_from_challenge() {
        let challenge = sample_challenge("abc1234567890DEFghij-KLMNOP");
        let context = Http01KeyAuthorization::from_challenge(
            &challenge,
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        )
        .expect("geçerli context oluşturulmalı");
        assert_eq!(context.token(), "abc1234567890DEFghij-KLMNOP");
        assert_eq!(
            context.key_authorization(),
            "abc1234567890DEFghij-KLMNOP.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        );
    }

    #[test]
    fn rejects_non_http01_challenge() {
        let authorization = Authorization::from_json_value(json!({
            "status": "pending",
            "identifier": {"type": "dns", "value": "example.com"},
            "challenges": [
                {
                    "type": "dns-01",
                    "status": "pending",
                    "url": "https://acme.invalid/challenge/1",
                    "token": "abc1234567890DEFghij-KLMNOP",
                }
            ]
        }))
        .expect("authorization ayrıştırılmalı");
        let challenge = authorization
            .challenges()
            .first()
            .expect("challenge mevcut olmalı")
            .clone();
        let err = Http01KeyAuthorization::from_challenge(
            &challenge,
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        )
        .unwrap_err();
        assert!(matches!(err, Http01ValidationError::NotHttp01));
    }

    #[test]
    fn rejects_thumbprint_with_wrong_length() {
        let err =
            Http01KeyAuthorization::new("gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH", "short")
                .unwrap_err();
        assert!(matches!(
            err,
            Http01ValidationError::InvalidThumbprint { reason }
                if reason == "thumbprint base64url formatında olmalıdır"
                    || reason == "thumbprint SHA-256 (32 bayt) uzunluğunda olmalıdır"
        ));
    }

    #[test]
    fn verify_body_accepts_trailing_newline() {
        let context = Http01KeyAuthorization::new(
            "gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH",
            "ytxINsp8lvQ1mX8kGqCFyT9OQy2M7o1uz7NErHOwhwU",
        )
        .expect("context oluşturulmalı");
        let body = format!("{}\n", context.key_authorization());
        context
            .verify_body(&body)
            .expect("son satır sonu göz ardı edilmeli");
    }

    #[test]
    fn verify_body_rejects_mismatch() {
        let context = Http01KeyAuthorization::new(
            "gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH",
            "ytxINsp8lvQ1mX8kGqCFyT9OQy2M7o1uz7NErHOwhwU",
        )
        .expect("context oluşturulmalı");
        let err = context
            .verify_body("unexpected value")
            .expect_err("hatalı body reddedilmeli");
        if let Http01ValidationError::BodyMismatch { expected, received } = err {
            assert_eq!(
                expected,
                "gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH.ytxINsp8lvQ1mX8kGqCFyT9OQy2M7o1uz7NErHOwhwU"
            );
            assert_eq!(received, "unexpected value");
        } else {
            panic!("beklenmeyen hata: {err:?}");
        }
    }

    #[test]
    fn builds_dns01_record_from_authorization() {
        let authorization = Authorization::from_json_value(json!({
            "status": "pending",
            "identifier": {"type": "dns", "value": "example.com"},
            "challenges": [
                {
                    "type": "dns-01",
                    "status": "pending",
                    "url": "https://acme.invalid/challenge/1",
                    "token": "gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH",
                }
            ]
        }))
        .expect("authorization ayrıştırılmalı");
        let challenge = authorization
            .challenges()
            .first()
            .expect("challenge mevcut olmalı");
        let record = Dns01TxtRecord::from_authorization(
            &authorization,
            challenge,
            "ytxINsp8lvQ1mX8kGqCFyT9OQy2M7o1uz7NErHOwhwU",
        )
        .expect("DNS-01 kaydı oluşturulmalı");
        assert_eq!(record.name(), "_acme-challenge.example.com");
        assert_eq!(
            record.value(),
            "X1WjMMFxcIhXcEU6oMwAFrf3Ymk622YZVSoBHxgkzuM"
        );
    }

    #[test]
    fn dns01_record_strips_wildcard_prefix() {
        let identifier =
            OrderIdentifier::dns("*.Example.com").expect("identifier normalleştirilmeli");
        let record = Dns01TxtRecord::new(
            "gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH",
            &identifier,
            "ytxINsp8lvQ1mX8kGqCFyT9OQy2M7o1uz7NErHOwhwU",
        )
        .expect("DNS-01 kaydı oluşturulmalı");
        assert_eq!(record.name(), "_acme-challenge.example.com");
    }

    #[test]
    fn dns01_record_rejects_non_dns_identifier() {
        let identifier = OrderIdentifier::ip("192.0.2.10").expect("ip identifier oluşturulmalı");
        let err = Dns01TxtRecord::new(
            "gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH",
            &identifier,
            "ytxINsp8lvQ1mX8kGqCFyT9OQy2M7o1uz7NErHOwhwU",
        )
        .expect_err("DNS olmayan identifier reddedilmeli");
        assert!(matches!(err, Dns01ValidationError::UnsupportedIdentifier));
    }

    #[test]
    fn dns01_record_rejects_non_dns_challenge() {
        let authorization = Authorization::from_json_value(json!({
            "status": "pending",
            "identifier": {"type": "dns", "value": "example.com"},
            "challenges": [
                {
                    "type": "http-01",
                    "status": "pending",
                    "url": "https://acme.invalid/challenge/1",
                    "token": "gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH",
                }
            ]
        }))
        .expect("authorization ayrıştırılmalı");
        let challenge = authorization
            .challenges()
            .first()
            .expect("challenge mevcut olmalı");
        let err = Dns01TxtRecord::from_authorization(
            &authorization,
            challenge,
            "ytxINsp8lvQ1mX8kGqCFyT9OQy2M7o1uz7NErHOwhwU",
        )
        .expect_err("DNS olmayan challenge reddedilmeli");
        assert!(matches!(err, Dns01ValidationError::NotDns01));
    }

    #[test]
    fn tls_alpn_challenge_builds_digest() {
        let authorization = Authorization::from_json_value(json!({
            "status": "pending",
            "identifier": {"type": "dns", "value": "*.Example.com"},
            "challenges": [
                {
                    "type": "tls-alpn-01",
                    "status": "pending",
                    "url": "https://acme.invalid/challenge/42",
                    "token": "gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH",
                }
            ]
        }))
        .expect("authorization ayrıştırılmalı");
        let challenge = authorization
            .challenges()
            .first()
            .expect("challenge mevcut olmalı")
            .clone();
        let context = TlsAlpnChallenge::from_authorization(
            &authorization,
            &challenge,
            "ytxINsp8lvQ1mX8kGqCFyT9OQy2M7o1uz7NErHOwhwU",
        )
        .expect("TLS-ALPN bağlamı oluşturulmalı");
        assert_eq!(context.domain(), "example.com");
        assert_eq!(TlsAlpnChallenge::ALPN_PROTOCOL, "acme-tls/1");
        let digest = context.digest();
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn tls_alpn_challenge_rejects_non_dns_identifier() {
        let identifier = OrderIdentifier::ip("192.0.2.10").expect("ip identifier");
        let err = TlsAlpnChallenge::new(
            "gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH",
            &identifier,
            "ytxINsp8lvQ1mX8kGqCFyT9OQy2M7o1uz7NErHOwhwU",
        )
        .expect_err("IP identifier TLS-ALPN tarafından reddedilmeli");
        assert!(matches!(err, TlsAlpnValidationError::UnsupportedIdentifier));
    }

    #[test]
    fn tls_alpn_certificate_contains_acme_extension() {
        let authorization = Authorization::from_json_value(json!({
            "status": "pending",
            "identifier": {"type": "dns", "value": "example.com"},
            "challenges": [
                {
                    "type": "tls-alpn-01",
                    "status": "pending",
                    "url": "https://acme.invalid/challenge/1",
                    "token": "abc1234567890DEFghij-KLMNOP",
                }
            ]
        }))
        .expect("authorization ayrıştırılmalı");
        let challenge = authorization
            .challenges()
            .first()
            .expect("challenge mevcut olmalı")
            .clone();
        let context = TlsAlpnChallenge::from_authorization(
            &authorization,
            &challenge,
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        )
        .expect("TLS-ALPN bağlamı oluşturulmalı");
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let certificate = context
            .create_certificate_with_rng(&mut rng)
            .expect("sertifika oluşturulmalı");
        assert_eq!(certificate.domain(), "example.com");
        assert_eq!(certificate.alpn_protocol(), "acme-tls/1");
        assert_eq!(certificate.key_authorization_digest(), context.digest());

        let (_, parsed) = x509_parser::parse_x509_certificate(certificate.certificate_der())
            .expect("sertifika ayrıştırılmalı");

        let san = parsed
            .extensions()
            .iter()
            .find_map(|ext| match ext.parsed_extension() {
                ParsedExtension::SubjectAlternativeName(san) => Some(san),
                _ => None,
            })
            .expect("SAN uzantısı bulunmalı");
        let dns_names: Vec<String> = san
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::DNSName(value) => Some((*value).to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(dns_names, vec!["example.com".to_string()]);

        let mut expected_extension = Vec::with_capacity(34);
        expected_extension.push(0x04); // OCTET STRING
        expected_extension.push(0x20); // length 32
        expected_extension.extend_from_slice(context.digest());

        let acme_oid = Oid::from(&[1, 3, 6, 1, 5, 5, 7, 1, 31]).expect("acmeIdentifier OID");
        let acme_ext = parsed
            .extensions()
            .iter()
            .find(|ext| ext.oid == acme_oid)
            .expect("acmeIdentifier uzantısı bulunmalı");
        assert!(acme_ext.critical);
        assert_eq!(acme_ext.value, expected_extension.as_slice());

        assert!(certificate.certificate_pem().contains("BEGIN CERTIFICATE"));
        assert!(certificate.private_key_pem().contains("BEGIN PRIVATE KEY"));
    }
}
