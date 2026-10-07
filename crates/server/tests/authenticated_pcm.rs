//! Real envelope integration controls; the AAD convention below is test-only.
#![forbid(unsafe_code)]

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use aunsorm_core::AunsormNativeRng;
use aunsorm_server::{AudioPcmDatagram, DatagramPayload, QuicDatagramV1, MAX_WIRE_BYTES};
use rand_core::RngCore;

fn aad(frame: &QuicDatagramV1, context: &[u8; 32]) -> Result<Vec<u8>, String> {
    let mut header = frame.clone();
    let DatagramPayload::Audio(audio) = &mut header.payload else {
        return Err("expected audio".to_owned());
    };
    audio.payload.clear();
    let mut bytes = b"aunsorm/pcm-envelope-integration-test/v1\0".to_vec();
    bytes.extend_from_slice(context);
    bytes.extend_from_slice(&header.encode().map_err(|error| error.to_string())?);
    Ok(bytes)
}

fn seal(
    frame: &QuicDatagramV1,
    cipher: &Aes256Gcm,
    prefix: &[u8; 8],
    context: &[u8; 32],
) -> Result<QuicDatagramV1, String> {
    let DatagramPayload::Audio(audio) = &frame.payload else {
        return Err("expected audio".to_owned());
    };
    if audio.payload.len() > 960 - 12 - 16 {
        return Err("plaintext leaves no room for nonce/tag envelope".to_owned());
    }
    // Fresh key/prefix per test frame; counters are distinct for its shards.
    // A production sender needs reviewed lifecycle/rekeying and replay state.
    let mut nonce_bytes = [0; 12];
    nonce_bytes[..8].copy_from_slice(prefix);
    nonce_bytes[8..].copy_from_slice(&u32::from(audio.fragment_index).to_le_bytes());
    let associated = aad(frame, context)?;
    let encrypted = cipher
        .encrypt(
            &Nonce::from(nonce_bytes),
            Payload {
                msg: &audio.payload,
                aad: &associated,
            },
        )
        .map_err(|_| "encryption failed".to_owned())?;
    let mut sealed = frame.clone();
    let DatagramPayload::Audio(output) = &mut sealed.payload else {
        return Err("expected audio".to_owned());
    };
    output.payload = nonce_bytes.to_vec();
    output.payload.extend(encrypted);
    sealed.encode().map_err(|error| error.to_string())?;
    Ok(sealed)
}

fn open(
    frame: &QuicDatagramV1,
    cipher: &Aes256Gcm,
    context: &[u8; 32],
) -> Result<QuicDatagramV1, String> {
    let DatagramPayload::Audio(audio) = &frame.payload else {
        return Err("expected audio".to_owned());
    };
    if audio.payload.len() < 28 {
        return Err("truncated nonce/tag envelope".to_owned());
    }
    let mut nonce_bytes = [0; 12];
    nonce_bytes.copy_from_slice(&audio.payload[..12]);
    let associated = aad(frame, context)?;
    let plaintext = cipher
        .decrypt(
            &Nonce::from(nonce_bytes),
            Payload {
                msg: &audio.payload[12..],
                aad: &associated,
            },
        )
        .map_err(|_| "authentication failed".to_owned())?;
    let mut opened = frame.clone();
    let DatagramPayload::Audio(output) = &mut opened.payload else {
        return Err("expected audio".to_owned());
    };
    output.payload = plaintext;
    Ok(opened)
}

fn material() -> (Aes256Gcm, [u8; 8], [u8; 32]) {
    let mut rng = AunsormNativeRng::new();
    let mut key = [0; 32];
    let mut prefix = [0; 8];
    let mut context = [0; 32];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut prefix);
    rng.fill_bytes(&mut context);
    (Aes256Gcm::new_from_slice(&key).unwrap(), prefix, context)
}

fn pcm() -> Vec<u8> {
    (0..AudioPcmDatagram::FRAME_BYTES)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect()
}

#[test]
fn encrypted_fragments_fit_wire_budget_and_reassemble_after_authentication() {
    let (cipher, prefix, context) = material();
    let source = pcm();
    let shards = QuicDatagramV1::from_pcm_frame_with_fragment_bytes(
        u32::MAX - 1,
        1000,
        7,
        &source,
        960 - 12 - 16,
    )
    .unwrap();
    assert_eq!(shards.len(), 3);
    let mut opened = Vec::new();
    for shard in &shards {
        let encrypted = seal(shard, &cipher, &prefix, &context).unwrap();
        let encoded = encrypted.encode().unwrap();
        assert!(encoded.len() <= MAX_WIRE_BYTES);
        let decoded = QuicDatagramV1::decode(&encoded).unwrap();
        opened.push(open(&decoded, &cipher, &context).unwrap());
    }
    assert!(QuicDatagramV1::reassemble_pcm_frame(&opened[..2]).is_err());
    opened.reverse();
    assert_eq!(
        QuicDatagramV1::reassemble_pcm_frame(&opened).unwrap(),
        source
    );
    let default = QuicDatagramV1::from_pcm_frame(1, 1000, 7, &source).unwrap();
    assert!(seal(&default[0], &cipher, &prefix, &context).is_err());
}

#[test]
fn ciphertext_nonce_header_context_and_key_changes_reject_authentication() {
    let (cipher, prefix, context) = material();
    let (other_cipher, _, other_context) = material();
    let shards =
        QuicDatagramV1::from_pcm_frame_with_fragment_bytes(1, 1000, 7, &pcm(), 932).unwrap();
    let sealed = seal(&shards[0], &cipher, &prefix, &context).unwrap();
    assert!(open(&sealed, &cipher, &other_context).is_err());
    assert!(open(&sealed, &other_cipher, &context).is_err());
    for field in 0..8 {
        let mut changed = sealed.clone();
        match field {
            0 => changed.sequence += 1,
            1 => changed.timestamp_ms += 1,
            _ => {
                let DatagramPayload::Audio(audio) = &mut changed.payload else {
                    panic!("expected audio");
                };
                match field {
                    2 => audio.stream_id += 1,
                    3 => audio.fragment_index += 1,
                    4 => audio.fragment_count += 1,
                    5 => audio.payload[0] ^= 1,
                    6 => audio.payload[12] ^= 1,
                    _ => {
                        let last = audio.payload.len() - 1;
                        audio.payload[last] ^= 1;
                    }
                }
            }
        }
        // These mutations retain valid structural metadata. AEAD must reject.
        assert!(changed.encode().is_ok());
        assert!(open(&changed, &cipher, &context).is_err());
    }
    let mut truncated = sealed;
    let DatagramPayload::Audio(audio) = &mut truncated.payload else {
        panic!("expected audio");
    };
    audio.payload.truncate(27);
    assert!(open(&truncated, &cipher, &context).is_err());
}

#[test]
fn plaintext_budget_boundaries_preserve_default_and_complete_samples() {
    let source = pcm();
    let expected = QuicDatagramV1::from_pcm_frame(1, 1000, 7, &source).unwrap();
    for budget in [8, 12, 64, 932, 944, 960] {
        let fragments =
            QuicDatagramV1::from_pcm_frame_with_fragment_bytes(1, 1000, 7, &source, budget)
                .unwrap();
        assert_eq!(
            QuicDatagramV1::reassemble_pcm_frame(&fragments).unwrap(),
            source
        );
        if budget == 960 {
            assert_eq!(fragments, expected);
        }
    }
    for budget in [0, 2, 6, 7, 9, 959, 961, usize::MAX] {
        assert!(
            QuicDatagramV1::from_pcm_frame_with_fragment_bytes(1, 1000, 7, &source, budget)
                .is_err()
        );
    }
}
