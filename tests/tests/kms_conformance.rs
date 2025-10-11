//! Harici KMS/HSM conformance fixture'larının tutarlılığını doğrular.

use std::collections::BTreeSet;
use std::convert::TryInto;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
struct CertificationRef {
    name: String,
    url: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "vector_type", rename_all = "snake_case")]
enum Vector {
    Signing(SigningVector),
    Wrap(WrapVector),
}

#[derive(Debug, Deserialize)]
struct SigningVector {
    resource: String,
    message_b64: String,
    signature_b64: String,
    public_key_b64: String,
    kid: String,
}

#[derive(Debug, Deserialize)]
struct WrapVector {
    key_reference: String,
    wrapping_key_b64: String,
    aad_b64: String,
    plaintext_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
    tag_b64: String,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    version: u8,
    provider: String,
    capability: String,
    fips_level: String,
    certification_refs: Vec<CertificationRef>,
    vector: Vector,
}

#[derive(Debug, Deserialize)]
struct CertificationReport {
    version: u8,
    generated_at: String,
    fixtures: Vec<String>,
    notes: String,
}

const GCP_FIXTURE: &str = include_str!("../fixtures/kms/kms_gcp_ed25519.json");
const AZURE_FIXTURE: &str = include_str!("../fixtures/kms/kms_azure_aes_wrap.json");
const PKCS11_FIXTURE: &str = include_str!("../fixtures/kms/kms_pkcs11_ed25519.json");
const CERTIFICATION_REPORT: &str = include_str!("../fixtures/kms/kms_certification_report.json");

#[test]
fn kms_conformance_vectors_are_cryptographically_consistent() {
    let fixtures = [GCP_FIXTURE, AZURE_FIXTURE, PKCS11_FIXTURE];
    for raw in fixtures {
        let fixture: Fixture = serde_json::from_str(raw).expect("fixture json");
        assert_eq!(fixture.version, 1, "fixture version must be 1");
        assert!(matches!(
            fixture.provider.as_str(),
            "gcp" | "azure" | "pkcs11"
        ));
        assert!(!fixture.capability.is_empty(), "capability must be set");
        assert!(fixture.fips_level.starts_with("FIPS 140"));
        assert!(
            !fixture.certification_refs.is_empty(),
            "certification references must not be empty"
        );
        for cert in &fixture.certification_refs {
            assert!(
                !cert.name.trim().is_empty(),
                "certification reference name must not be empty"
            );
            assert!(
                cert.url.starts_with("http"),
                "certification reference url must include scheme"
            );
        }

        match &fixture.vector {
            Vector::Signing(vector) => verify_signing_vector(&fixture, vector),
            Vector::Wrap(vector) => verify_wrap_vector(&fixture, vector),
        }
        .expect("fixture verification");
    }
}

#[test]
fn certification_report_lists_all_vectors() {
    let report: CertificationReport =
        serde_json::from_str(CERTIFICATION_REPORT).expect("report json");
    assert_eq!(report.version, 1);
    assert!(
        report.generated_at.contains('T'),
        "timestamp must be RFC3339-like"
    );
    assert!(report.notes.contains("fixtures"));

    let expected: BTreeSet<&str> = [
        "kms_gcp_ed25519.json",
        "kms_azure_aes_wrap.json",
        "kms_pkcs11_ed25519.json",
    ]
    .into_iter()
    .collect();
    let actual: BTreeSet<&str> = report.fixtures.iter().map(String::as_str).collect();
    assert_eq!(
        actual, expected,
        "report should reference all fixture files"
    );
}

fn verify_signing_vector(fixture: &Fixture, vector: &SigningVector) -> Result<(), String> {
    let message = B64
        .decode(vector.message_b64.as_bytes())
        .map_err(|err| format!("invalid message base64 for {}: {err}", fixture.provider))?;
    let signature_bytes = B64
        .decode(vector.signature_b64.as_bytes())
        .map_err(|err| format!("invalid signature base64 for {}: {err}", fixture.provider))?;
    let public_bytes = B64
        .decode(vector.public_key_b64.as_bytes())
        .map_err(|err| format!("invalid public key base64 for {}: {err}", fixture.provider))?;
    let public_array: [u8; 32] = public_bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("public key length mismatch for {}", fixture.provider))?;
    let verifying_key = VerifyingKey::from_bytes(&public_array)
        .map_err(|err| format!("invalid verifying key for {}: {err}", fixture.provider))?;
    let signature_array: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("signature length mismatch for {}", fixture.provider))?;
    let signature = Signature::from_bytes(&signature_array);
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|err| {
            format!(
                "signature verification failed for {}: {err}",
                fixture.provider
            )
        })?;
    let expected_kid = hex::encode(Sha256::digest(verifying_key.as_bytes()));
    if expected_kid != vector.kid {
        return Err(format!(
            "kid mismatch for {}: expected {expected_kid}, got {}",
            fixture.provider, vector.kid
        ));
    }
    if fixture.provider != "pkcs11" {
        // PKCS#11 fixture simulates remote HSM signing through opaque handles,
        // bu nedenle resource alanı farklı olabilir.
        assert!(
            vector.resource.contains('/'),
            "resource should contain path separators"
        );
    } else {
        assert!(
            !vector.resource.is_empty(),
            "pkcs11 resource identifiers must be non-empty"
        );
    }
    Ok(())
}

fn verify_wrap_vector(fixture: &Fixture, vector: &WrapVector) -> Result<(), String> {
    let wrapping_key = B64
        .decode(vector.wrapping_key_b64.as_bytes())
        .map_err(|err| {
            format!(
                "invalid wrapping key base64 for {}: {err}",
                fixture.provider
            )
        })?;
    if wrapping_key.len() != 32 {
        return Err(format!(
            "wrapping key length mismatch for {}: {}",
            fixture.provider,
            wrapping_key.len()
        ));
    }
    let aad = B64
        .decode(vector.aad_b64.as_bytes())
        .map_err(|err| format!("invalid aad base64 for {}: {err}", fixture.provider))?;
    let plaintext = B64
        .decode(vector.plaintext_b64.as_bytes())
        .map_err(|err| format!("invalid plaintext base64 for {}: {err}", fixture.provider))?;
    let nonce_bytes = B64
        .decode(vector.nonce_b64.as_bytes())
        .map_err(|err| format!("invalid nonce base64 for {}: {err}", fixture.provider))?;
    if nonce_bytes.len() != 12 {
        return Err(format!(
            "nonce length mismatch for {}: {}",
            fixture.provider,
            nonce_bytes.len()
        ));
    }
    let ciphertext = B64
        .decode(vector.ciphertext_b64.as_bytes())
        .map_err(|err| format!("invalid ciphertext base64 for {}: {err}", fixture.provider))?;
    let tag = B64
        .decode(vector.tag_b64.as_bytes())
        .map_err(|err| format!("invalid tag base64 for {}: {err}", fixture.provider))?;
    if tag.len() != 16 {
        return Err(format!(
            "tag length mismatch for {}: {}",
            fixture.provider,
            tag.len()
        ));
    }

    let mut combined = ciphertext;
    combined.extend_from_slice(&tag);
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key)
        .map_err(|err| format!("invalid aes key for {}: {err}", fixture.provider))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let decrypted = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &combined,
                aad: &aad,
            },
        )
        .map_err(|err| format!("wrap decrypt failed for {}: {err}", fixture.provider))?;
    if decrypted != plaintext {
        return Err(format!(
            "plaintext mismatch for {}: expected {:?}, got {:?}",
            fixture.provider, plaintext, decrypted
        ));
    }
    assert!(vector.key_reference.contains('/'));
    Ok(())
}
