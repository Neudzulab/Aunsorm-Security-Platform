use std::sync::atomic::{AtomicUsize, Ordering};

use aunsorm_acme::{
    async_trait, ChallengeState, Dns01StateMachine, Dns01ValidationError, DnsProvider,
    DnsProviderError, DnsRecordHandle, OrderIdentifier,
};
use serde::Deserialize;
use tokio::sync::Mutex;

#[derive(Deserialize)]
struct Dns01Fixture {
    description: String,
    token: String,
    identifier: String,
    thumbprint: String,
    expected_name: String,
    expected_value: String,
}

#[derive(Deserialize)]
struct DnsMockFixture {
    description: String,
    provider: String,
    zone: String,
    record: DnsMockRecord,
}

#[derive(Deserialize)]
struct DnsMockRecord {
    fqdn: String,
    value: String,
}

const DNS01_FIXTURE: &str = include_str!("../../data/acme/dns01_fixture.json");
const DNS_MOCK_PUBLISH: &str = include_str!("../../data/acme/dns_mock_publish.json");
const DNS_MOCK_OPERATIONS: &str = include_str!("../../data/acme/dns_mock_operations.json");

#[derive(Debug)]
struct MockDnsProvider {
    zone_id: String,
    expected_name: String,
    expected_value: String,
    published: Mutex<Option<DnsRecordHandle>>,
    propagation_ready: Mutex<bool>,
    sequence: AtomicUsize,
}

impl MockDnsProvider {
    const PROVIDER_NAME: &'static str = "mock-dns";

    fn new(fixture: &DnsMockFixture) -> Self {
        assert_eq!(fixture.provider, Self::PROVIDER_NAME);
        assert!(!fixture.description.trim().is_empty());
        Self {
            zone_id: fixture.zone.clone(),
            expected_name: fixture.record.fqdn.clone(),
            expected_value: fixture.record.value.clone(),
            published: Mutex::new(None),
            propagation_ready: Mutex::new(false),
            sequence: AtomicUsize::new(0),
        }
    }

    async fn allow_propagation(&self, allow: bool) {
        *self.propagation_ready.lock().await = allow;
    }
}

#[async_trait]
impl DnsProvider for MockDnsProvider {
    async fn publish_txt_record(
        &self,
        record: &aunsorm_acme::Dns01TxtRecord,
    ) -> Result<DnsRecordHandle, DnsProviderError> {
        if record.name() != self.expected_name {
            return Err(DnsProviderError::Provider {
                message: format!(
                    "Beklenen TXT kaydı {expected} iken {actual} yayınlanmaya çalışıldı",
                    expected = self.expected_name,
                    actual = record.name()
                ),
            });
        }
        if record.value() != self.expected_value {
            return Err(DnsProviderError::Validation(
                Dns01ValidationError::RecordMismatch {
                    expected: self.expected_value.clone(),
                    received: vec![record.value().to_owned()],
                },
            ));
        }
        let next = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let record_id = format!("{}-{:04}", self.zone_id, next);
        let handle = DnsRecordHandle::new(
            Self::PROVIDER_NAME,
            record_id,
            record.name().to_owned(),
            record.value().to_owned(),
        );
        *self.published.lock().await = Some(handle.clone());
        Ok(handle)
    }

    async fn revoke_txt_record(
        &self,
        handle: &DnsRecordHandle,
    ) -> Result<ChallengeState, DnsProviderError> {
        let mut guard = self.published.lock().await;
        let Some(current) = guard.as_ref() else {
            return Err(DnsProviderError::Provider {
                message: "Yayınlanmış TXT kaydı bulunamadı".to_owned(),
            });
        };
        if current.record_id() != handle.record_id() {
            return Err(DnsProviderError::Provider {
                message: format!(
                    "Beklenen kayıt kimliği {expected} iken {actual} gönderildi",
                    expected = current.record_id(),
                    actual = handle.record_id()
                ),
            });
        }
        *guard = None;
        drop(guard);
        *self.propagation_ready.lock().await = false;
        Ok(ChallengeState::Revoked)
    }

    async fn verify_propagation(
        &self,
        handle: &DnsRecordHandle,
    ) -> Result<ChallengeState, DnsProviderError> {
        let guard = self.published.lock().await;
        let Some(current) = guard.as_ref() else {
            return Err(DnsProviderError::Provider {
                message: "Yayınlanmış TXT kaydı bulunamadı".to_owned(),
            });
        };
        if current.record_id() != handle.record_id() {
            return Err(DnsProviderError::Provider {
                message: format!(
                    "Beklenen kayıt kimliği {expected} iken {actual} doğrulanmak istendi",
                    expected = current.record_id(),
                    actual = handle.record_id()
                ),
            });
        }
        drop(guard);
        let propagated = *self.propagation_ready.lock().await;
        if propagated {
            Ok(ChallengeState::Verified)
        } else {
            Ok(ChallengeState::Published)
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn publish_verify_revoke_flow() {
    let dns_fixture: Dns01Fixture = serde_json::from_str(DNS01_FIXTURE).expect("dns01 fixture");
    assert!(!dns_fixture.description.trim().is_empty());
    let mock_fixture: DnsMockFixture =
        serde_json::from_str(DNS_MOCK_PUBLISH).expect("mock publish fixture");
    assert_eq!(dns_fixture.expected_name, mock_fixture.record.fqdn);
    assert_eq!(dns_fixture.expected_value, mock_fixture.record.value);
    let identifier =
        OrderIdentifier::dns(&dns_fixture.identifier).expect("dns identifier oluşturulmalı");
    let mut machine =
        Dns01StateMachine::new(&dns_fixture.token, &identifier, &dns_fixture.thumbprint)
            .expect("durum makinesi oluşmalı");

    let publication = machine.publication();
    assert_eq!(publication.record_name(), mock_fixture.record.fqdn);
    assert_eq!(publication.record_value(), mock_fixture.record.value);

    let provider = MockDnsProvider::new(&mock_fixture);

    let state = machine
        .publish_with_provider(&provider)
        .await
        .expect("publish başarılı olmalı");
    assert_eq!(state, ChallengeState::Published);
    let handle = machine
        .record_handle()
        .expect("publish sonrası handle oluşmalı")
        .clone();

    let initial_state = machine
        .verify_with_provider(&provider)
        .await
        .expect("ilk doğrulama yayınlanmış durumda kalmalı");
    assert_eq!(initial_state, ChallengeState::Published);

    provider.allow_propagation(true).await;
    let verified_state = machine
        .verify_with_provider(&provider)
        .await
        .expect("propagasyon sonrası doğrulama başarılı olmalı");
    assert_eq!(verified_state, ChallengeState::Verified);
    assert_eq!(machine.state(), ChallengeState::Verified);

    let revoked_state = machine
        .revoke_with_provider(&provider)
        .await
        .expect("revoke başarılı olmalı");
    assert_eq!(revoked_state, ChallengeState::Revoked);
    assert_eq!(machine.state(), ChallengeState::Revoked);
    assert!(machine.record_handle().is_none());

    // Provider artık kayıt tutmamalı.
    assert!(
        provider.verify_propagation(&handle).await.is_err(),
        "revoked kayıt doğrulanmamalı"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn operations_require_publication() {
    let dns_fixture: Dns01Fixture = serde_json::from_str(DNS01_FIXTURE).expect("dns01 fixture");
    let mock_fixture: DnsMockFixture =
        serde_json::from_str(DNS_MOCK_OPERATIONS).expect("mock operations fixture");
    assert_eq!(dns_fixture.expected_name, mock_fixture.record.fqdn);
    assert_eq!(dns_fixture.expected_value, mock_fixture.record.value);
    let identifier =
        OrderIdentifier::dns(&dns_fixture.identifier).expect("dns identifier oluşturulmalı");
    let mut machine =
        Dns01StateMachine::new(&dns_fixture.token, &identifier, &dns_fixture.thumbprint)
            .expect("durum makinesi oluşmalı");
    let provider = MockDnsProvider::new(&mock_fixture);

    let verify_err = machine
        .verify_with_provider(&provider)
        .await
        .expect_err("publish öncesi verify hata üretmeli");
    match verify_err {
        DnsProviderError::Provider { message } => {
            assert_eq!(message, "TXT kaydı henüz yayınlanmadı");
        }
        other => panic!("beklenmeyen hata: {other:?}"),
    }

    let revoke_err = machine
        .revoke_with_provider(&provider)
        .await
        .expect_err("publish öncesi revoke hata üretmeli");
    match revoke_err {
        DnsProviderError::Provider { message } => {
            assert_eq!(message, "TXT kaydı yayınlanmadan revoke işlemi çağrılamaz");
        }
        other => panic!("beklenmeyen hata: {other:?}"),
    }
    assert_eq!(machine.state(), ChallengeState::Pending);
    assert!(machine.record_handle().is_none());
}
