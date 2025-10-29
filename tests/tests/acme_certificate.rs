use std::fs;
use std::sync::Arc;

use aunsorm_acme::{
    build_finalize_payload, download_certificate_chain, CertificateBundle, CertificateError,
    CertificateStorage,
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

        let pem_chain = format!(
            "{}\n{}",
            server.certificate_pem.trim(),
            root.certificate_pem.trim()
        );
        let url = Url::parse("https://acme.test/cert/1").expect("url");
        let download = download_certificate_chain(&url, |_: &Url| async {
            Ok::<_, CertificateError>(pem_chain.clone())
        })
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
