//! Bounded canonical Ed25519 `CKA_EC_POINT` encoding shared with fuzz controls.

/// Decode the supported single or legacy double DER OCTET STRING.
///
/// A 32-byte payload needs only DER's short length form. Matching the complete
/// fixed encoding avoids arithmetic on untrusted length fields and allocations.
/// Raw points, trailing data, nonminimal lengths and further nesting are rejected.
pub fn parse_ed25519_point(data: &[u8]) -> Result<[u8; 32], &'static str> {
    let bytes = match data {
        [0x04, 0x20, bytes @ ..] | [0x04, 0x22, 0x04, 0x20, bytes @ ..] if bytes.len() == 32 => {
            bytes
        }
        _ => {
            return Err(
                "ed25519 ec point must be a complete canonical single or double DER OCTET STRING",
            );
        }
    };
    bytes
        .try_into()
        .map_err(|_| "ed25519 public key must be 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::parse_ed25519_point;

    #[test]
    fn canonical_single_double_and_payload_tag_are_preserved() {
        for first in [0, 4, 255] {
            let mut key = [27u8; 32];
            key[0] = first;
            for prefix in [vec![4, 32], vec![4, 34, 4, 32]] {
                let mut encoded = prefix;
                encoded.extend_from_slice(&key);
                assert_eq!(parse_ed25519_point(&encoded).expect("canonical point"), key);
            }
        }
    }

    #[test]
    fn every_truncation_trailing_byte_and_extra_nesting_rejects() {
        let key = [42u8; 32];
        let mut single = vec![4, 32];
        single.extend_from_slice(&key);
        let mut double = vec![4, 34];
        double.extend_from_slice(&single);
        for canonical in [&single, &double] {
            for end in 0..canonical.len() {
                assert!(parse_ed25519_point(&canonical[..end]).is_err());
            }
            let mut trailing = canonical.clone();
            trailing.push(0);
            assert!(parse_ed25519_point(&trailing).is_err());
        }
        let mut triple = vec![4, 36];
        triple.extend_from_slice(&double);
        assert!(parse_ed25519_point(&triple).is_err());
        assert!(parse_ed25519_point(&key).is_err());
    }

    #[test]
    fn nonminimal_indefinite_and_overflow_lengths_reject() {
        for header in [
            vec![4, 0x81, 32],
            vec![4, 0x82, 0, 32],
            vec![4, 0x80],
            vec![4, 0xff],
            vec![4, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            vec![4, 31],
            vec![4, 33],
        ] {
            let mut input = header;
            input.extend_from_slice(&[21u8; 32]);
            assert!(parse_ed25519_point(&input).is_err());
        }
    }

    #[test]
    fn public_bytes_verify_an_actual_ed25519_signature() {
        use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

        let signing = SigningKey::from_bytes(&[21u8; 32]);
        let public = signing.verifying_key();
        let mut encoded = vec![4, 32];
        encoded.extend_from_slice(public.as_bytes());
        let decoded = parse_ed25519_point(&encoded).expect("canonical point");
        let verifying = VerifyingKey::from_bytes(&decoded).expect("valid public key");
        let signature = signing.sign(b"actual key decoding regression");
        verifying
            .verify_strict(b"actual key decoding regression", &signature)
            .expect("actual signature verification");
        assert!(verifying
            .verify_strict(b"different message", &signature)
            .is_err());
    }
}
