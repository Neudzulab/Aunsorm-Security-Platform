use serde::{Deserialize, Serialize};

use crate::{
    authorization::{Authorization, Challenge},
    order::OrderIdentifier,
    providers::dns::{DnsProvider, DnsProviderError, DnsRecordHandle},
};

use super::{ChallengeState, Dns01TxtRecord, Dns01ValidationError};

/// DNS-01 TXT kaydı yayın çıktısı.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dns01Publication {
    record_name: String,
    record_value: String,
}

#[allow(clippy::missing_const_for_fn)]
impl Dns01Publication {
    /// TXT kaydı için tam alan adını döndürür.
    #[must_use]
    pub fn record_name(&self) -> &str {
        self.record_name.as_str()
    }

    /// TXT kaydının değerini döndürür.
    #[must_use]
    pub fn record_value(&self) -> &str {
        self.record_value.as_str()
    }
}

/// DNS-01 challenge durum makinesi.
#[derive(Debug, Clone)]
pub struct Dns01StateMachine {
    record: Dns01TxtRecord,
    state: ChallengeState,
    handle: Option<DnsRecordHandle>,
}

impl Dns01StateMachine {
    /// Token, identifier ve hesap thumbprint bilgileriyle yeni bir durum makinesi oluşturur.
    /// # Errors
    ///
    /// DNS dışı identifier kullanıldığında veya token/thumbprint doğrulaması
    /// başarısız olduğunda [`Dns01ValidationError`] döndürülür.
    pub fn new(
        token: &str,
        identifier: &OrderIdentifier,
        account_thumbprint: &str,
    ) -> Result<Self, Dns01ValidationError> {
        let record = Dns01TxtRecord::new(token, identifier, account_thumbprint)?;
        Ok(Self {
            record,
            state: ChallengeState::Pending,
            handle: None,
        })
    }

    /// Authorization ve challenge bilgilerinden durum makinesi oluşturur.
    /// # Errors
    ///
    /// Challenge DNS-01 türünde değilse, token alanı eksikse veya key-authorization
    /// doğrulaması başarısız olursa [`Dns01ValidationError`] döndürülür.
    pub fn from_authorization(
        authorization: &Authorization,
        challenge: &Challenge,
        account_thumbprint: &str,
    ) -> Result<Self, Dns01ValidationError> {
        let record =
            Dns01TxtRecord::from_authorization(authorization, challenge, account_thumbprint)?;
        Ok(Self {
            record,
            state: ChallengeState::Pending,
            handle: None,
        })
    }

    /// Güncel challenge durumunu döndürür.
    #[must_use]
    pub const fn state(&self) -> ChallengeState {
        self.state
    }

    /// Yayınlanacak TXT kaydı çıktısını döndürür.
    #[must_use]
    pub fn publication(&self) -> Dns01Publication {
        Dns01Publication {
            record_name: self.record.name().to_owned(),
            record_value: self.record.value().to_owned(),
        }
    }

    /// Yayınlanan TXT kaydı tanımlayıcısını döndürür.
    #[must_use]
    pub const fn record_handle(&self) -> Option<&DnsRecordHandle> {
        self.handle.as_ref()
    }

    /// Challenge'ı yayınlanmış olarak işaretler.
    #[allow(clippy::missing_const_for_fn)]
    pub fn publish(&mut self) -> ChallengeState {
        self.state = ChallengeState::Published;
        self.state
    }

    /// DNS sağlayıcısı üzerinden TXT kaydı yayınlar.
    ///
    /// # Errors
    ///
    /// Sağlayıcı kimlik doğrulaması, doğrulama veya işlem hatası dönerse
    /// [`DnsProviderError`] hatası üretilir.
    pub async fn publish_with_provider(
        &mut self,
        provider: &dyn DnsProvider,
    ) -> Result<ChallengeState, DnsProviderError> {
        let handle = provider.publish_txt_record(&self.record).await?;
        self.handle = Some(handle);
        self.state = ChallengeState::Published;
        Ok(self.state)
    }

    /// DNS sorgularından dönen TXT kayıtlarını doğrular.
    /// # Errors
    ///
    /// TXT kaydı bulunamaz veya beklenen değerden farklıysa
    /// [`Dns01ValidationError::MissingRecord`] ya da [`Dns01ValidationError::RecordMismatch`]
    /// döndürülür.
    pub fn verify_records(
        &mut self,
        records: &[String],
    ) -> Result<ChallengeState, Dns01ValidationError> {
        let trimmed: Vec<String> = records
            .iter()
            .map(|value| value.trim().to_owned())
            .collect();
        if trimmed.iter().any(|value| value == self.record.value()) {
            self.state = ChallengeState::Verified;
            Ok(self.state)
        } else {
            self.state = ChallengeState::Invalid;
            if trimmed.is_empty() {
                Err(Dns01ValidationError::MissingRecord)
            } else {
                Err(Dns01ValidationError::RecordMismatch {
                    expected: self.record.value().to_owned(),
                    received: trimmed,
                })
            }
        }
    }

    /// DNS sağlayıcısı üzerinden TXT yayılım durumunu doğrular.
    ///
    /// # Errors
    ///
    /// TXT kaydı henüz yayınlanmadıysa veya sağlayıcı işlem hatası döndürürse
    /// [`DnsProviderError`] hatası üretilir.
    pub async fn verify_with_provider(
        &mut self,
        provider: &dyn DnsProvider,
    ) -> Result<ChallengeState, DnsProviderError> {
        let handle = self
            .handle
            .as_ref()
            .ok_or_else(|| DnsProviderError::Provider {
                message: "TXT kaydı henüz yayınlanmadı".to_owned(),
            })?;
        let state = provider.verify_propagation(handle).await?;
        self.state = state;
        Ok(self.state)
    }

    /// TXT kaydını geri çağırır.
    #[allow(clippy::missing_const_for_fn)]
    pub fn revoke(&mut self) -> ChallengeState {
        self.handle = None;
        self.state = ChallengeState::Revoked;
        self.state
    }

    /// DNS sağlayıcısı üzerinden TXT kaydını geri çağırır.
    ///
    /// # Errors
    ///
    /// TXT kaydı yayınlanmadıysa veya sağlayıcı işlem hatası döndürürse
    /// [`DnsProviderError`] hatası oluşur.
    pub async fn revoke_with_provider(
        &mut self,
        provider: &dyn DnsProvider,
    ) -> Result<ChallengeState, DnsProviderError> {
        let handle = self
            .handle
            .as_ref()
            .ok_or_else(|| DnsProviderError::Provider {
                message: "TXT kaydı yayınlanmadan revoke işlemi çağrılamaz".to_owned(),
            })?;
        let state = provider.revoke_txt_record(handle).await?;
        self.state = state;
        if matches!(self.state, ChallengeState::Revoked) {
            self.handle = None;
        }
        Ok(self.state)
    }

    /// İç kayıt yapısını döndürür.
    #[must_use]
    pub const fn record(&self) -> &Dns01TxtRecord {
        &self.record
    }
}

#[cfg(test)]
mod tests {
    use super::Dns01StateMachine;
    use crate::{
        order::OrderIdentifier,
        validation::{ChallengeState, Dns01ValidationError},
    };

    #[test]
    fn publish_and_verify_dns_record() {
        let identifier = OrderIdentifier::dns("example.com").expect("identifier");
        let mut machine = Dns01StateMachine::new(
            "gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH",
            &identifier,
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        )
        .expect("durum makinesi oluşmalı");

        assert_eq!(machine.state(), ChallengeState::Pending);
        let publication = machine.publication();
        assert_eq!(publication.record_name(), "_acme-challenge.example.com");

        machine.publish();
        assert_eq!(machine.state(), ChallengeState::Published);

        let verified = machine
            .verify_records(&[publication.record_value().to_string()])
            .expect("doğrulama başarılı olmalı");
        assert_eq!(verified, ChallengeState::Verified);

        let revoked = machine.revoke();
        assert_eq!(revoked, ChallengeState::Revoked);
    }

    #[test]
    fn record_mismatch_sets_invalid_state() {
        let identifier = OrderIdentifier::dns("example.com").expect("identifier");
        let mut machine = Dns01StateMachine::new(
            "gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH",
            &identifier,
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        )
        .expect("durum makinesi oluşmalı");
        machine.publish();

        let err = machine
            .verify_records(&["yanlis".to_string()])
            .expect_err("hatalı kayıt hata üretmeli");
        assert!(matches!(err, Dns01ValidationError::RecordMismatch { .. }));
        assert_eq!(machine.state(), ChallengeState::Invalid);
    }

    #[test]
    fn missing_record_sets_invalid_state() {
        let identifier = OrderIdentifier::dns("example.com").expect("identifier");
        let mut machine = Dns01StateMachine::new(
            "gDn1sRZqXo9Nhc2ZtF1S7gT4u0Lk-pQ8R6aBcDeFgH",
            &identifier,
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        )
        .expect("durum makinesi oluşmalı");
        machine.publish();

        let err = machine
            .verify_records(&[])
            .expect_err("kayıt yoksa hata üretmeli");
        assert!(matches!(err, Dns01ValidationError::MissingRecord));
        assert_eq!(machine.state(), ChallengeState::Invalid);
    }
}
