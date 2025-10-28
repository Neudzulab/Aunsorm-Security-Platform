use aunsorm_acme::{AcmeDirectory, NoncePool, ReplayNonce, REPLAY_NONCE_HEADER};
use http::HeaderMap;

#[test]
fn directory_parsing_smoke() {
    let json = r#"{
        "newNonce": "https://acme.example/acme/new-nonce",
        "newAccount": "https://acme.example/acme/new-account",
        "newOrder": "https://acme.example/acme/new-order",
        "revokeCert": "https://acme.example/acme/revoke-cert",
        "keyChange": "https://acme.example/acme/key-change",
        "meta": {
            "termsOfService": "https://acme.example/terms",
            "website": "https://acme.example/docs",
            "caaIdentities": ["acme.example"],
            "externalAccountRequired": false
        }
    }"#;

    let directory = AcmeDirectory::from_json_str(json).expect("directory parse");
    assert_eq!(
        directory.new_nonce.as_str(),
        "https://acme.example/acme/new-nonce"
    );
    assert_eq!(
        directory.new_account.as_str(),
        "https://acme.example/acme/new-account"
    );
    assert!(directory.meta.as_ref().is_some_and(|meta| {
        meta.terms_of_service
            .as_ref()
            .is_some_and(|url| url.as_str() == "https://acme.example/terms")
    }));
}

#[test]
fn nonce_pool_absorb_smoke() {
    let mut pool = NoncePool::with_default_capacity();
    let mut headers = HeaderMap::new();
    headers.insert(REPLAY_NONCE_HEADER, "dGVzdC1ub25jZQ".parse().unwrap());

    let absorbed = pool
        .absorb_replay_nonce_header(&headers)
        .expect("header parsing");
    assert!(absorbed.is_some());
    assert_eq!(pool.len(), 1);

    let nonce = pool.pop().expect("nonce from pool");
    assert_eq!(nonce, ReplayNonce::parse("dGVzdC1ub25jZQ").unwrap());
}
