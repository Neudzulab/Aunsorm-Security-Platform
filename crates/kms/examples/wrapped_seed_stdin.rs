#![forbid(unsafe_code)]

use std::io::{self, Read, Write};

#[path = "../src/wrapped_seed.rs"]
mod wrapped_seed;

fn main() -> io::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--seed") {
        return emit_fixture();
    }
    let mut data = Vec::new();
    io::stdin().take(1105).read_to_end(&mut data)?;
    if data.len() > 1104 {
        return Ok(());
    }
    let split = data.len().min(80);
    let (envelope, aad) = data.split_at(split);
    if let Ok(seed) = wrapped_seed::unwrap(&[7u8; 32], envelope, aad) {
        assert_eq!(seed.len(), 32);
        assert!(wrapped_seed::unwrap(&[8u8; 32], envelope, aad).is_err());
        let mut changed_aad = aad.to_vec();
        changed_aad.push(0);
        assert!(wrapped_seed::unwrap(&[7u8; 32], envelope, &changed_aad).is_err());
        println!("accepted");
    } else {
        println!("rejected");
    }
    Ok(())
}

fn emit_fixture() -> io::Result<()> {
    use aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use rand_core::RngCore;

    let mut rng = aunsorm_kms::AunsormNativeRng::new();
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&[7u8; 32]).expect("synthetic wrapping key");
    let encrypted = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &[21u8; 32],
                aad: b"pkcs-key",
            },
        )
        .expect("synthetic fixture encryption");
    let mut envelope = nonce.to_vec();
    envelope.extend_from_slice(&encrypted);
    let encoded = STANDARD.encode(envelope);
    let actual = wrapped_seed::unwrap(&[7u8; 32], encoded.as_bytes(), b"pkcs-key")
        .expect("real fixture decryption");
    assert_eq!(*actual, [21u8; 32]);
    io::stdout().write_all(encoded.as_bytes())?;
    io::stdout().write_all(b"pkcs-key")
}
