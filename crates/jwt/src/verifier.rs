use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier as _};
use serde::Deserialize;

use crate::claims::{Audience, Claims};
use crate::error::{JwtError, Result};
use crate::jti::JtiStore;
use crate::jwk::{Ed25519PublicKey, Jwks};

/// JWT doğrulayıcı yapılandırması.
#[derive(Clone)]
pub struct JwtVerifier {
    keys: HashMap<String, Ed25519PublicKey>,
    default_kid: Option<String>,
    store: Option<Arc<dyn JtiStore>>,
    leeway: Duration,
}

impl JwtVerifier {
    /// Anahtar koleksiyonu ile doğrulayıcı oluşturur.
    pub fn new<I>(keys: I) -> Self
    where
        I: IntoIterator<Item = Ed25519PublicKey>,
    {
        let mut map = HashMap::new();
        let mut default_kid = None;
        for key in keys {
            default_kid.get_or_insert_with(|| key.kid().to_owned());
            map.insert(key.kid().to_owned(), key);
        }
        Self {
            keys: map,
            default_kid,
            store: None,
            leeway: Duration::from_secs(30),
        }
    }

    /// JWKS ile doğrulayıcı oluşturur.
    ///
    /// # Errors
    ///
    /// Sağlanan JWK'lar Ed25519/EdDSA formatında değilse hata döner.
    pub fn from_jwks(jwks: &Jwks) -> Result<Self> {
        let map = jwks.to_map()?;
        let default_kid = map.keys().next().cloned();
        Ok(Self {
            keys: map,
            default_kid,
            store: None,
            leeway: Duration::from_secs(30),
        })
    }

    /// JTI store ekler.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn with_store(mut self, store: Arc<dyn JtiStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Leeway süresi belirler.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn with_leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    /// JWT'yi doğrular ve claim'leri döndürür.
    ///
    /// # Errors
    ///
    /// İmza doğrulaması, claim kontrolleri veya JTI store işlemleri başarısız olursa `JwtError` döner.
    pub fn verify(&self, token: &str, options: &VerificationOptions) -> Result<Claims> {
        let mut segments = token.split('.');
        let header_part = segments.next().ok_or(JwtError::Malformed)?;
        let payload_part = segments.next().ok_or(JwtError::Malformed)?;
        let signature_part = segments.next().ok_or(JwtError::Malformed)?;
        if segments.next().is_some() {
            return Err(JwtError::Malformed);
        }

        let header_raw = URL_SAFE_NO_PAD
            .decode(header_part)
            .map_err(|_| JwtError::Malformed)?;
        let payload_raw = URL_SAFE_NO_PAD
            .decode(payload_part)
            .map_err(|_| JwtError::Malformed)?;
        let signature_raw = URL_SAFE_NO_PAD
            .decode(signature_part)
            .map_err(|_| JwtError::Malformed)?;

        let header: Header = serde_json::from_slice(&header_raw)?;
        if header.alg != "EdDSA" {
            return Err(JwtError::UnsupportedAlgorithm(header.alg));
        }
        if let Some(ref typ) = header.typ {
            if typ != "JWT" {
                return Err(JwtError::InvalidClaim("typ", "must be JWT"));
            }
        }
        let kid = header
            .kid
            .or_else(|| self.default_kid.clone())
            .ok_or(JwtError::MissingKeyId)?;
        let key = self
            .keys
            .get(&kid)
            .ok_or_else(|| JwtError::UnknownKey(kid.clone()))?;
        let mut signing_input = Vec::with_capacity(header_part.len() + payload_part.len() + 1);
        signing_input.extend_from_slice(header_part.as_bytes());
        signing_input.push(b'.');
        signing_input.extend_from_slice(payload_part.as_bytes());
        let signature = Signature::from_slice(&signature_raw).map_err(|_| JwtError::Signature)?;
        key.verifying_key()
            .verify(&signing_input, &signature)
            .map_err(|_| JwtError::Signature)?;
        let claims: Claims = serde_json::from_slice(&payload_raw)?;
        self.validate_claims(&claims, options)?;

        let jti = claims.jwt_id.as_deref();
        if options.require_jti && jti.is_none() {
            return Err(JwtError::MissingJti);
        }

        if let Some(store) = &self.store {
            if let Some(jti_value) = jti {
                let expires_at = claims.expiration;
                if !store.check_and_insert(jti_value, expires_at)? {
                    return Err(JwtError::Replay);
                }
            }
        } else if options.require_jti {
            return Err(JwtError::MissingJtiStore);
        }
        Ok(claims)
    }

    fn validate_claims(&self, claims: &Claims, options: &VerificationOptions) -> Result<()> {
        claims.validate_custom_claims()?;
        let now = options.now.unwrap_or_else(SystemTime::now);
        let leeway = self.leeway;
        claims.validate_temporal_consistency()?;
        if let Some(exp) = claims.expiration {
            if now
                .duration_since(exp)
                .map(|elapsed| elapsed > leeway)
                .unwrap_or(false)
            {
                return Err(JwtError::Expired);
            }
        }
        if let Some(nbf) = claims.not_before {
            if nbf
                .duration_since(now)
                .map(|delta| delta > leeway)
                .unwrap_or(false)
            {
                return Err(JwtError::NotYetValid);
            }
        }
        if let Some(iat) = claims.issued_at {
            if iat
                .duration_since(now)
                .map(|delta| delta > leeway)
                .unwrap_or(false)
            {
                return Err(JwtError::IssuedInFuture);
            }
        }
        if let Some(expected) = &options.issuer {
            if claims.issuer.as_deref() != Some(expected.as_str()) {
                return Err(JwtError::ClaimMismatch("iss"));
            }
        }
        if let Some(expected) = &options.subject {
            if claims.subject.as_deref() != Some(expected.as_str()) {
                return Err(JwtError::ClaimMismatch("sub"));
            }
        }
        if let Some(expected_aud) = &options.audience {
            match &claims.audience {
                Some(Audience::Single(aud)) if aud == expected_aud => {}
                Some(Audience::Multiple(list)) if list.iter().any(|aud| aud == expected_aud) => {}
                _ => return Err(JwtError::ClaimMismatch("aud")),
            }
        }
        Ok(())
    }
}

/// Doğrulama seçenekleri.
#[derive(Debug, Clone)]
pub struct VerificationOptions {
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub audience: Option<String>,
    pub require_jti: bool,
    pub now: Option<SystemTime>,
}

impl Default for VerificationOptions {
    fn default() -> Self {
        Self {
            issuer: None,
            subject: None,
            audience: None,
            require_jti: true,
            now: None,
        }
    }
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
    #[serde(default)]
    typ: Option<String>,
}
