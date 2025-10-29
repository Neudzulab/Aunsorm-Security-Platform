use std::collections::VecDeque;
use std::fs;
use std::future::{ready, Ready};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aunsorm_acme::{
    build_finalize_payload, finalize_and_download_certificate, AcmeJws, CertificateBundle,
    CertificateError, CertificateStorage, FinalizeOptions, FinalizeWorkflow, OrderService,
    OrderStatus, OrderStatusSnapshot,
};
use aunsorm_kms::{BackendKind, BackendLocator, KmsClient, KmsConfig};
use aunsorm_x509::ca::{
    generate_certificate_signing_request, sign_server_cert, verify_certificate_chain,
    CertificateSigningRequestParams, KeyAlgorithm, RootCaParams, ServerCertParams,
};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use pem::parse as parse_pem;
use serde_json::{self, Value};
use tempfile::tempdir;
use tokio::runtime::Runtime;
use url::Url;

#[derive(Clone)]
struct StubOrderStatus {
    status: OrderStatus,
    certificate_url: Option<String>,
    retry_after: Option<Duration>,
}

impl StubOrderStatus {
    fn new(status: OrderStatus) -> Self {
        Self {
            status,
            certificate_url: None,
            retry_after: None,
        }
    }

    fn with_certificate(mut self, url: impl Into<String>) -> Self {
        self.certificate_url = Some(url.into());
        self
    }

    fn with_retry_after(mut self, delay: Duration) -> Self {
        self.retry_after = Some(delay);
        self
    }
}

impl OrderStatusSnapshot for StubOrderStatus {
    fn status(&self) -> OrderStatus {
        self.status
    }

    fn certificate_url(&self) -> Option<&str> {
        self.certificate_url.as_deref()
    }

    fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }
}

#[derive(Debug)]
struct StubError;

impl std::fmt::Display for StubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("stub error")
    }
}

impl std::error::Error for StubError {}

struct StubOrderService {
    finalize_response: StubOrderStatus,
    poll_responses: Arc<Mutex<VecDeque<StubOrderStatus>>>,
}

impl StubOrderService {
    fn new(finalize_response: StubOrderStatus, poll_responses: Vec<StubOrderStatus>) -> Self {
        Self {
            finalize_response,
            poll_responses: Arc::new(Mutex::new(VecDeque::from(poll_responses))),
        }
    }
}

impl OrderService for StubOrderService {
    type Error = StubError;
    type NewOrder = ();
    type LookupOrder = StubOrderStatus;
    type FinalizeOrder = StubOrderStatus;
    type RevokeOutcome = ();

    type NewOrderFuture<'a> = Ready<Result<Self::NewOrder, Self::Error>>;
    type LookupFuture<'a>
        = Pin<
        Box<dyn std::future::Future<Output = Result<Self::LookupOrder, Self::Error>> + Send + 'a>,
    >
    where
        Self: 'a;
    type FinalizeFuture<'a>
        = Pin<
        Box<dyn std::future::Future<Output = Result<Self::FinalizeOrder, Self::Error>> + Send + 'a>,
    >
    where
        Self: 'a;
    type RevokeFuture<'a>
        = Ready<Result<Self::RevokeOutcome, Self::Error>>
    where
        Self: 'a;

    fn create_order(&self, _jws: AcmeJws) -> Self::NewOrderFuture<'_> {
        ready(Ok(()))
    }

    fn query_order<'a>(&'a self, _order_id: &'a str, _jws: AcmeJws) -> Self::LookupFuture<'a> {
        let responses = Arc::clone(&self.poll_responses);
        let fallback = self.finalize_response.clone();
        Box::pin(async move {
            let mut guard = responses.lock().expect("poll queue lock");
            Ok(guard.pop_front().unwrap_or_else(|| fallback.clone()))
        })
    }

    fn finalize_order<'a>(&'a self, _order_id: &'a str, _jws: AcmeJws) -> Self::FinalizeFuture<'a> {
        let response = self.finalize_response.clone();
        Box::pin(async move { Ok(response) })
    }

    fn revoke_certificate(&self, _jws: AcmeJws) -> Self::RevokeFuture<'_> {
        ready(Ok(()))
    }
}

fn blank_jws() -> AcmeJws {
    AcmeJws {
        protected: String::new(),
        payload: String::new(),
        signature: String::new(),
    }
}

#[test]
fn finalize_payload_contains_csr_der() {
    let csr = generate_certificate_signing_request(&CertificateSigningRequestParams {
        common_name: "example.com",
        subject_alt_names: &[],
        key_algorithm: Some(KeyAlgorithm::Ed25519),
    })
    .expect("csr generation");

    let payload = build_finalize_payload(&csr.csr_pem).expect("payload");
    let decoded = URL_SAFE_NO_PAD
        .decode(payload.csr.as_bytes())
        .expect("base64 decode");
    let parsed = parse_pem(csr.csr_pem).expect("csr pem");
    assert_eq!(decoded, parsed.contents());
}

#[test]
fn certificate_download_and_storage_flow() {
    let rt = Runtime::new().expect("rt");
    rt.block_on(async {
        let root_params = RootCaParams {
            common_name: "Integration Root",
            org_salt: b"integration-salt",
            calibration_text: "Integration Root Calibration",
            validity_days: 3650,
            cps_uris: &[],
            policy_oids: &[],
            key_algorithm: Some(KeyAlgorithm::Ed25519),
        };
        let root = aunsorm_x509::ca::generate_root_ca(&root_params).expect("root");

        let server_params = ServerCertParams {
            hostname: "example.com",
            org_salt: b"integration-salt",
            calibration_text: "Integration Server",
            ca_cert_pem: &root.certificate_pem,
            ca_key_pem: &root.private_key_pem,
            validity_days: 365,
            extra_dns: &[],
            extra_ips: &[],
            key_algorithm: Some(KeyAlgorithm::Ed25519),
        };
        let server = sign_server_cert(&server_params).expect("server");

        let csr_params = CertificateSigningRequestParams {
            common_name: "example.com",
            subject_alt_names: &[],
            key_algorithm: Some(KeyAlgorithm::Ed25519),
        };
        let csr = generate_certificate_signing_request(&csr_params).expect("csr generation");

        let certificate_url = Url::parse("https://acme.test/cert/1").expect("url");
        let pem_chain = format!(
            "{}\n{}",
            server.certificate_pem.trim(),
            root.certificate_pem.trim()
        );
        let finalize_status = StubOrderStatus::new(OrderStatus::Processing)
            .with_retry_after(Duration::from_millis(1));
        let poll_responses = vec![
            StubOrderStatus::new(OrderStatus::Processing)
                .with_retry_after(Duration::from_millis(1)),
            StubOrderStatus::new(OrderStatus::Valid).with_certificate(certificate_url.as_str()),
        ];
        let service = StubOrderService::new(finalize_status, poll_responses);
        let expected_url = certificate_url.clone();
        let fetcher_pem = pem_chain.clone();
        let fetcher = move |url: &Url| {
            assert_eq!(url.as_str(), expected_url.as_str());
            let pem_chain = fetcher_pem.clone();
            async move { Ok::<_, CertificateError>(pem_chain) }
        };
        let workflow = FinalizeWorkflow::new(
            |_payload, _csr| Ok(blank_jws()),
            |_order_id: String| Ok(blank_jws()),
            fetcher,
            |_delay| async {},
        )
        .with_options(FinalizeOptions::new(4));
        let download = finalize_and_download_certificate(&service, "order-123", &csr, workflow)
            .await
            .expect("download");
        assert_eq!(download.certificates().len(), 2);

        let intermediates: Vec<&str> = download
            .intermediates()
            .iter()
            .map(String::as_str)
            .collect();
        let root_cert = download.root().expect("root cert");
        let chain_validation =
            verify_certificate_chain(download.leaf(), &intermediates, root_cert).expect("chain");
        assert_eq!(chain_validation.subjects.len(), 2);

        let bundle = CertificateBundle::from_download(&download, server.private_key_pem.clone())
            .expect("bundle");

        let dir = tempdir().expect("tempdir");
        let certificate_path = dir.path().join("cert.pem");
        let chain_path = dir.path().join("fullchain.pem");
        let private_key_path = dir.path().join("privkey.pem");
        let local = CertificateStorage::local(&certificate_path, &chain_path, &private_key_path);
        let local_outcome = local.store(&bundle).expect("local store");
        assert!(local_outcome.private_key_path.is_some());
        let stored_leaf = fs::read_to_string(local_outcome.certificate_path).expect("leaf");
        assert!(stored_leaf.contains("BEGIN CERTIFICATE"));
        let stored_key = fs::read_to_string(local_outcome.private_key_path.unwrap()).expect("key");
        assert!(stored_key.contains("BEGIN PRIVATE KEY"));

        let kms_store_path = dir.path().join("kms.json");
        let aes_key = [0x42u8; 32];
        let store_json = serde_json::json!({
            "keys": [
                {
                    "id": "tls-wrap",
                    "purpose": "aes256-wrap",
                    "secret": STANDARD.encode(aes_key),
                }
            ]
        });
        fs::write(
            &kms_store_path,
            serde_json::to_vec_pretty(&store_json).expect("kms json"),
        )
        .expect("write kms");
        let kms_config = KmsConfig::local_only(&kms_store_path).expect("kms config");
        let kms_client = Arc::new(KmsClient::from_config(kms_config).expect("kms client"));
        let wrap_locator = BackendLocator::new(BackendKind::Local, "tls-wrap");
        let wrapped_key_path = dir.path().join("wrapped.json");
        let kms_storage = CertificateStorage::kms(
            Arc::clone(&kms_client),
            wrap_locator.clone(),
            dir.path().join("kms-cert.pem"),
            dir.path().join("kms-chain.pem"),
            wrapped_key_path.clone(),
        );
        let kms_outcome = kms_storage.store(&bundle).expect("kms store");
        assert!(kms_outcome.private_key_path.is_none());
        let wrapped = fs::read_to_string(kms_outcome.wrapped_key_path.unwrap()).expect("wrapped");
        let wrapped_json: Value = serde_json::from_str(&wrapped).expect("json");
        let ciphertext = URL_SAFE_NO_PAD
            .decode(wrapped_json["ciphertext_b64"].as_str().expect("ciphertext"))
            .expect("cipher decode");
        let aad = URL_SAFE_NO_PAD
            .decode(wrapped_json["aad_b64"].as_str().expect("aad"))
            .expect("aad decode");
        let unwrapped = kms_client
            .unwrap_key(&wrap_locator, &ciphertext, &aad)
            .expect("unwrap");
        assert_eq!(unwrapped, server.private_key_pem.as_bytes());
    });
}
