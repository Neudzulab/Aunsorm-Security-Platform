use std::error::Error;

use aunsorm_core::{
    calib_from_text,
    kdf::{KdfPreset, KdfProfile},
    salts::Salts,
    SessionRatchet,
};
use aunsorm_packet::{
    decrypt_one_shot,
    decrypt_session,
    encrypt_one_shot,
    encrypt_session,
    AeadAlgorithm,
    DecryptParams,
    EncryptParams,
    SessionDecryptParams,
    SessionEncryptParams,
    SessionStore,
};

fn to_hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    const PASSWORD: &str = "correct horse battery staple";
    const CALIB_TEXT: &str = "Neudzulab | Prod | 2025-08";
    let profile = KdfProfile::preset(KdfPreset::Low);
    let (calibration, calib_id) = calib_from_text(b"demo-org", CALIB_TEXT);

    let password_salt = *b"bootstrap-salt!!";
    let salts = Salts::new(
        b"session-calib-salt-2025".to_vec(),
        b"session-chain-salt-2025".to_vec(),
        b"session-coord-salt-2025".to_vec(),
    )?;

    let bootstrap_packet = encrypt_one_shot(EncryptParams {
        password: PASSWORD,
        password_salt: &password_salt,
        calibration: &calibration,
        salts: &salts,
        plaintext: b"bootstrap", // küçük bir tetikleyici yük
        aad: b"bootstrap aad",
        profile,
        algorithm: AeadAlgorithm::Chacha20Poly1305,
        strict: false,
        kem: None,
    })?;
    let bootstrap_b64 = bootstrap_packet.to_base64()?;
    println!(
        "bootstrap packet ready | calib_id={calib_id} | ciphertext_len={}",
        bootstrap_packet.ciphertext.len()
    );

    let bootstrap_ok = decrypt_one_shot(&DecryptParams {
        password: PASSWORD,
        password_salt: &password_salt,
        calibration: &calibration,
        salts: &salts,
        profile,
        aad: b"bootstrap aad",
        strict: false,
        packet: &bootstrap_b64,
    })?;
    println!(
        "bootstrap decrypt ok | coord_digest={} | plaintext={}",
        bootstrap_ok.header.coord_digest,
        String::from_utf8_lossy(&bootstrap_ok.plaintext)
    );

    let metadata = bootstrap_ok.metadata;
    let session_id = [0xA5; 16];
    let root_key = [0x3C_u8; 32];
    let mut sender = SessionRatchet::new(root_key, session_id, false);
    let mut receiver = SessionRatchet::new(root_key, session_id, false);

    let session_plaintext = b"session secret message";
    let session_aad = b"session aad";
    let (session_packet, outcome) = encrypt_session(SessionEncryptParams {
        ratchet: &mut sender,
        metadata: &metadata,
        plaintext: session_plaintext,
        aad: session_aad,
    })?;
    let session_b64 = session_packet.to_base64()?;
    println!(
        "session encrypt ok | session_id={} | msg_no={}",
        to_hex(&outcome.session_id),
        outcome.message_no
    );

    let mut store = SessionStore::new();
    let (session_ok, recv_outcome) = decrypt_session(SessionDecryptParams {
        ratchet: &mut receiver,
        metadata: &metadata,
        store: &mut store,
        aad: session_aad,
        packet: &session_b64,
    })?;
    println!(
        "session decrypt ok | msg_no={} | payload={}",
        recv_outcome.message_no,
        String::from_utf8_lossy(&session_ok.plaintext)
    );

    let replay = decrypt_session(SessionDecryptParams {
        ratchet: &mut receiver,
        metadata: &metadata,
        store: &mut store,
        aad: session_aad,
        packet: &session_b64,
    });
    println!(
        "replay attempt blocked = {}",
        replay
            .err()
            .map(|err| err.to_string())
            .unwrap_or_else(|| "unexpected success".to_string())
    );

    Ok(())
}
