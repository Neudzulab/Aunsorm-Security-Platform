//! Domain validation helpers for ACME challenges.

#![allow(clippy::module_name_repetitions)]

use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::authorization::{
    validate_token, Authorization, Challenge, ChallengeError, ChallengeKind,
};
use crate::order::OrderIdentifier;

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
            _ => return Err(Dns01ValidationError::UnsupportedIdentifier),
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

fn trim_trailing_http_whitespace(input: &str) -> &str {
    let without_newlines = input.trim_end_matches(['\n', '\r']);
    without_newlines.trim_end_matches([' ', '\t'])
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
    use serde_json::json;

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
}
