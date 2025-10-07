use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::json;

use crate::{
    Claims, Ed25519KeyPair, InMemoryJtiStore, JtiStore, JwtError, JwtSigner, JwtVerifier,
    VerificationOptions,
};

#[cfg(feature = "sqlite")]
use crate::SqliteJtiStore;

#[test]
fn sign_and_verify_roundtrip() {
    let mut rng = StdRng::seed_from_u64(42);
    let key = Ed25519KeyPair::generate_with_rng("kid-1", &mut rng).expect("key");
    let signer = JwtSigner::new(key.clone());
    let mut claims = Claims::new();
    claims.issuer = Some("https://issuer".into());
    claims.subject = Some("user-1".into());
    claims.audience = Some(crate::Audience::Single("api".into()));
    claims.set_issued_now();
    claims.set_expiration_from_now(Duration::from_secs(600));
    claims.ensure_jwt_id();
    claims.extra.insert("role".into(), json!("admin"));

    let token = signer.sign(&claims).expect("jwt");

    let store = Arc::new(InMemoryJtiStore::default());
    let verifier =
        JwtVerifier::new([key.public_key()]).with_store(Arc::clone(&store) as Arc<dyn JtiStore>);
    let verified_claims = verifier
        .verify(&token, &VerificationOptions::default())
        .expect("verified");
    assert_eq!(verified_claims.subject, claims.subject);
    assert_eq!(verified_claims.extra.get("role"), Some(&json!("admin")));
}

#[test]
fn rejects_replay_in_memory_store() {
    let key = Ed25519KeyPair::generate("kid-replay").expect("key");
    let signer = JwtSigner::new(key.clone());
    let mut claims = Claims::new();
    claims.set_expiration_from_now(Duration::from_secs(60));
    claims.ensure_jwt_id();
    let token = signer.sign(&claims).expect("jwt");
    let store = Arc::new(InMemoryJtiStore::default());
    let verifier = JwtVerifier::new([key.public_key()]).with_store(store.clone());
    verifier
        .verify(&token, &VerificationOptions::default())
        .expect("first ok");
    let err = verifier
        .verify(&token, &VerificationOptions::default())
        .expect_err("replay");
    assert!(matches!(err, JwtError::Replay));
    // purge expired entries should be no-op since token still valid
    let _ = store
        .purge_expired(SystemTime::now() + Duration::from_secs(3600))
        .expect("purge");
}

#[test]
fn audience_and_claim_validation() {
    let key = Ed25519KeyPair::generate("kid-claim").expect("key");
    let signer = JwtSigner::new(key.clone());
    let mut claims = Claims::new();
    claims.issuer = Some("https://issuer".into());
    claims.subject = Some("user-123".into());
    claims.audience = Some(crate::Audience::Multiple(vec![
        "aud-a".into(),
        "aud-b".into(),
    ]));
    claims.set_expiration_from_now(Duration::from_secs(120));
    claims.ensure_jwt_id();
    let token = signer.sign(&claims).expect("jwt");
    let verifier = JwtVerifier::new([key.public_key()]);
    let options = VerificationOptions {
        issuer: Some("https://issuer".into()),
        subject: Some("user-123".into()),
        audience: Some("aud-b".into()),
        require_jti: true,
        ..VerificationOptions::default()
    };
    let verified_claims = verifier.verify(&token, &options).expect("valid token");
    assert_eq!(verified_claims.subject.as_deref(), Some("user-123"));

    let mut wrong = options;
    wrong.audience = Some("aud-x".into());
    let err = verifier
        .verify(&token, &wrong)
        .expect_err("audience mismatch");
    assert!(matches!(err, JwtError::ClaimMismatch("aud")));
}

#[test]
fn expired_token_is_rejected() {
    let key = Ed25519KeyPair::generate("kid-exp").expect("key");
    let signer = JwtSigner::new(key.clone());
    let mut claims = Claims::new();
    claims.set_expiration_from_now(Duration::from_secs(1));
    claims.ensure_jwt_id();
    let token = signer.sign(&claims).expect("jwt");
    let verifier = JwtVerifier::new([key.public_key()]).with_leeway(Duration::from_secs(0));
    std::thread::sleep(Duration::from_millis(1500));
    let err = verifier
        .verify(&token, &VerificationOptions::default())
        .expect_err("expired");
    assert!(matches!(err, JwtError::Expired));
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_store_roundtrip() {
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("jti.db");
    let store = Arc::new(SqliteJtiStore::open(&path).expect("store"));
    let key = Ed25519KeyPair::generate("kid-sqlite").expect("key");
    let signer = JwtSigner::new(key.clone());
    let mut claims = Claims::new();
    claims.set_expiration_from_now(Duration::from_secs(120));
    claims.ensure_jwt_id();
    let token = signer.sign(&claims).expect("jwt");
    let verifier = JwtVerifier::new([key.public_key()]).with_store(store.clone());
    verifier
        .verify(&token, &VerificationOptions::default())
        .expect("verified");
    let err = verifier
        .verify(&token, &VerificationOptions::default())
        .expect_err("replay");
    assert!(matches!(err, JwtError::Replay));
    let _ = store
        .purge_expired(SystemTime::now() + Duration::from_secs(3600))
        .expect("purge");
}
