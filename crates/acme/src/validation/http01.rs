use serde::{Deserialize, Serialize};

use crate::authorization::Challenge;

use super::{ChallengeState, Http01KeyAuthorization, Http01ValidationError};

/// HTTP-01 challenge yayın çıktısını temsil eder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Http01Publication {
    resource_path: String,
    body: String,
}

#[allow(clippy::missing_const_for_fn)]
impl Http01Publication {
    /// HTTP kaynağının servis edilmesi gereken yolu döndürür.
    #[must_use]
    pub fn resource_path(&self) -> &str {
        self.resource_path.as_str()
    }

    /// HTTP yanıt gövdesi olarak servis edilecek key-authorization değerini döndürür.
    #[must_use]
    pub fn body(&self) -> &str {
        self.body.as_str()
    }
}

/// HTTP-01 challenge durum makinesi.
#[derive(Debug, Clone)]
pub struct Http01StateMachine {
    context: Http01KeyAuthorization,
    state: ChallengeState,
}

impl Http01StateMachine {
    /// Ham token ve hesap thumbprint değerinden yeni bir durum makinesi oluşturur.
    ///
    /// # Errors
    ///
    /// Token RFC 8555 kurallarını ihlal ediyorsa veya thumbprint geçersizse
    /// [`Http01ValidationError`] döndürülür.
    pub fn for_token(token: &str, account_thumbprint: &str) -> Result<Self, Http01ValidationError> {
        let context = Http01KeyAuthorization::new(token, account_thumbprint)?;
        Ok(Self {
            context,
            state: ChallengeState::Pending,
        })
    }

    /// Ayrıştırılmış bir ACME challenge nesnesinden durum makinesi oluşturur.
    ///
    /// # Errors
    ///
    /// Challenge HTTP-01 türünde değilse veya token/thumbprint doğrulaması
    /// başarısız olursa [`Http01ValidationError`] döndürülür.
    pub fn from_challenge(
        challenge: &Challenge,
        account_thumbprint: &str,
    ) -> Result<Self, Http01ValidationError> {
        let context = Http01KeyAuthorization::from_challenge(challenge, account_thumbprint)?;
        Ok(Self {
            context,
            state: ChallengeState::Pending,
        })
    }

    /// Challenge durumunu döndürür.
    #[must_use]
    pub const fn state(&self) -> ChallengeState {
        self.state
    }

    /// Yayınlanacak HTTP içeriğini döndürür.
    #[must_use]
    pub fn publication(&self) -> Http01Publication {
        Http01Publication {
            resource_path: self.context.resource_path().to_owned(),
            body: self.context.key_authorization().to_owned(),
        }
    }

    /// Challenge'ı yayınlanmış olarak işaretler.
    #[allow(clippy::missing_const_for_fn)]
    pub fn publish(&mut self) -> ChallengeState {
        self.state = ChallengeState::Published;
        self.state
    }

    /// İstemciden alınan HTTP gövdesini doğrular.
    ///
    /// # Errors
    ///
    /// Gövde beklenen key-authorization değeriyle eşleşmezse
    /// [`Http01ValidationError::BodyMismatch`] döndürülür.
    pub fn verify_body(&mut self, body: &str) -> Result<ChallengeState, Http01ValidationError> {
        match self.context.verify_body(body) {
            Ok(()) => {
                self.state = ChallengeState::Verified;
                Ok(self.state)
            }
            Err(err) => {
                self.state = ChallengeState::Invalid;
                Err(err)
            }
        }
    }

    /// Challenge içeriğini geri çağırır ve durumu günceller.
    #[allow(clippy::missing_const_for_fn)]
    pub fn revoke(&mut self) -> ChallengeState {
        self.state = ChallengeState::Revoked;
        self.state
    }

    /// İç temel bağlamı döndürür.
    #[must_use]
    pub const fn context(&self) -> &Http01KeyAuthorization {
        &self.context
    }
}

#[cfg(test)]
mod tests {
    use super::Http01StateMachine;
    use crate::validation::{ChallengeState, Http01ValidationError};

    #[test]
    fn publish_and_verify_flow() {
        let mut machine = Http01StateMachine::for_token(
            "gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        )
        .expect("durum makinesi oluşmalı");

        assert_eq!(machine.state(), ChallengeState::Pending);
        let publication = machine.publication();
        assert_eq!(
            publication.resource_path(),
            "/.well-known/acme-challenge/gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH"
        );
        assert_eq!(
            publication.body(),
            "gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        );

        machine.publish();
        assert_eq!(machine.state(), ChallengeState::Published);

        let verified = machine
            .verify_body(publication.body())
            .expect("doğrulama başarılı olmalı");
        assert_eq!(verified, ChallengeState::Verified);

        let revoked = machine.revoke();
        assert_eq!(revoked, ChallengeState::Revoked);
    }

    #[test]
    fn invalid_body_transitions_to_error_state() {
        let mut machine = Http01StateMachine::for_token(
            "gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        )
        .expect("durum makinesi oluşmalı");
        machine.publish();

        let err = machine
            .verify_body("yanlis-yanit")
            .expect_err("yanlış gövde hata üretmeli");
        assert!(matches!(err, Http01ValidationError::BodyMismatch { .. }));
        assert_eq!(machine.state(), ChallengeState::Invalid);
    }
}
