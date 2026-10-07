//! Ed25519 identity/response checks shared with parser fuzz controls.

use ed25519_dalek::{Signature, VerifyingKey};

pub fn validate_public(public: &[u8; 32]) -> Result<VerifyingKey, &'static str> {
    let key =
        VerifyingKey::from_bytes(public).map_err(|_| "invalid Ed25519 public key encoding")?;
    if key.is_weak() {
        return Err("weak Ed25519 public key is not accepted");
    }
    Ok(key)
}

pub fn verify_response(
    public: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), &'static str> {
    let key = validate_public(public)?;
    let signature =
        Signature::from_slice(signature).map_err(|_| "Ed25519 signature must be 64 bytes")?;
    key.verify_strict(message, &signature)
        .map_err(|_| "Ed25519 signature does not match the selected public key and message")
}

#[cfg(test)]
mod tests {
    use super::{validate_public, verify_response};
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn actual_signature_binds_public_key_message_and_every_signature_byte() {
        let signing = SigningKey::from_bytes(&[21u8; 32]);
        let public = signing.verifying_key().to_bytes();
        let signature = signing.sign(b"actual response").to_bytes();
        assert!(verify_response(&public, b"actual response", &signature).is_ok());
        let other = SigningKey::from_bytes(&[22u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(verify_response(&other, b"actual response", &signature).is_err());
        assert!(verify_response(&public, b"changed response", &signature).is_err());
        for index in 0..64 {
            let mut changed = signature;
            changed[index] ^= 1;
            assert!(verify_response(&public, b"actual response", &changed).is_err());
        }
    }

    #[test]
    fn weak_public_and_noncanonical_scalar_responses_reject() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(validate_public(&identity).is_err());
        assert!(validate_public(&[0u8; 32]).is_err());
        let signing = SigningKey::from_bytes(&[21u8; 32]);
        let public = signing.verifying_key().to_bytes();
        let mut signature = signing.sign(b"actual response").to_bytes();
        signature[32..].fill(255);
        assert!(verify_response(&public, b"actual response", &signature).is_err());
    }

    #[test]
    fn signature_lengths_and_appended_bytes_are_rejected() {
        let signing = SigningKey::from_bytes(&[21u8; 32]);
        let public = signing.verifying_key().to_bytes();
        let signature = signing.sign(b"actual response").to_bytes();
        for end in 0..64 {
            assert!(verify_response(&public, b"actual response", &signature[..end]).is_err());
        }
        let mut trailing = signature.to_vec();
        trailing.push(0);
        assert!(verify_response(&public, b"actual response", &trailing).is_err());
    }
}
