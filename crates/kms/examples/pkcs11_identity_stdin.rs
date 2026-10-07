#![forbid(unsafe_code)]

use std::io::{self, Read, Write};

#[path = "../src/pkcs11_identity.rs"]
mod pkcs11_identity;

fn main() -> io::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--seed") {
        use ed25519_dalek::{Signer, SigningKey};
        let signing = SigningKey::from_bytes(&[21u8; 32]);
        let public = signing.verifying_key().to_bytes();
        let message = b"pkcs-identity";
        let signature = signing.sign(message).to_bytes();
        assert!(pkcs11_identity::verify_response(&public, message, &signature).is_ok());
        let mut output = io::stdout();
        output.write_all(&public)?;
        output.write_all(&signature)?;
        return output.write_all(message);
    }
    let mut data = Vec::new();
    io::stdin().take(1121).read_to_end(&mut data)?;
    if data.len() < 32 || data.len() > 1120 {
        println!("rejected");
        return Ok(());
    }
    let mut public = [0u8; 32];
    public.copy_from_slice(&data[..32]);
    let end = data.len().min(96);
    let signature = &data[32..end];
    let message = &data[end..];
    if pkcs11_identity::verify_response(&public, message, signature).is_ok() {
        let mut changed = message.to_vec();
        changed.push(0);
        assert!(pkcs11_identity::verify_response(&public, &changed, signature).is_err());
        println!("accepted");
    } else {
        println!("rejected");
    }
    Ok(())
}
