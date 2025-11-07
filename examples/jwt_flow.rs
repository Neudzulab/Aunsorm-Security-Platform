use std::sync::Arc;
use std::time::Duration;

use aunsorm_jwt::{
    Audience, Claims, Ed25519KeyPair, InMemoryJtiStore, JtiStore, Jwks, JwtSigner, JwtVerifier,
    VerificationOptions,
};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = "https://aunsorm.example";
    let subject = "user-123";
    let audience = "aunsorm-cli";

    let key = Ed25519KeyPair::generate("demo-key")?;
    let signer = JwtSigner::new(key.clone());

    let mut claims = Claims::new();
    claims.issuer = Some(issuer.to_owned());
    claims.subject = Some(subject.to_owned());
    claims.audience = Some(Audience::Single(audience.to_owned()));
    claims.set_issued_now();
    claims.set_expiration_from_now(Duration::from_secs(300));
    claims
        .extras
        .insert("role".to_owned(), json!("platform-admin"));
    claims.extras.insert(
        "scopes".to_owned(),
        json!(["encrypt", "decrypt", "session:manage"]),
    );

    let token = signer.sign(&mut claims)?;
    println!("Generated JWT: {token}");

    let jwks = Jwks {
        keys: vec![key.to_jwk()],
    };
    let store: Arc<dyn JtiStore> = Arc::new(InMemoryJtiStore::default());
    let verifier = JwtVerifier::from_jwks(&jwks)?
        .with_store(store)
        .with_leeway(Duration::from_secs(5));

    let options = VerificationOptions {
        issuer: Some(issuer.to_owned()),
        subject: Some(subject.to_owned()),
        audience: Some(audience.to_owned()),
        require_jti: true,
        now: None,
    };

    let validated = verifier.verify(&token, &options)?;
    let role = validated
        .extras
        .get("role")
        .and_then(|value| value.as_str())
        .unwrap_or("<missing role>");
    println!(
        "Token accepted for subject {} with role {role}",
        validated.subject.unwrap_or_else(|| "<unknown>".to_owned()),
    );

    match verifier.verify(&token, &options) {
        Ok(_) => println!("Unexpectedly accepted a replayed token."),
        Err(err) => println!("Replay detection triggered: {err}"),
    }

    Ok(())
}
