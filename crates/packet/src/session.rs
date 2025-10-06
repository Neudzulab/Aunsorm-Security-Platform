use std::collections::HashSet;

use zeroize::Zeroizing;

use aunsorm_core::session::SessionRatchet;

use crate::crypto::{
    aad_digest, base64_encode, compute_body_pmac, compute_header_mac, decrypt_aead, derive_keys,
    verify_body_pmac, verify_header_mac,
};
use crate::error::PacketError;
use crate::header::{
    AeadAlgorithm, Header, HeaderAead, HeaderKem, HeaderProfile, HeaderSalts, HeaderSession,
    HeaderSizes,
};
use crate::packet::{DecryptOk, Packet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMetadata {
    pub version: String,
    pub profile: HeaderProfile,
    pub calib_id: String,
    pub coord_digest: String,
    pub coord_id: Option<String>,
    pub coord: Option<[u8; 32]>,
    pub salts: HeaderSalts,
    pub kem: HeaderKem,
    pub algorithm: AeadAlgorithm,
}

impl SessionMetadata {
    #[must_use]
    pub fn from_header(header: &Header) -> Self {
        Self {
            version: header.version.clone(),
            profile: header.profile,
            calib_id: header.calib_id.clone(),
            coord_digest: header.coord_digest.clone(),
            coord_id: None,
            coord: None,
            salts: header.salts.clone(),
            kem: header.kem.clone(),
            algorithm: header.aead.alg,
        }
    }

    #[must_use]
    pub fn with_coord(mut self, coord_id: String, coord: [u8; 32]) -> Self {
        self.coord_id = Some(coord_id);
        self.coord = Some(coord);
        self
    }

    /// Verilen başlığın oturum meta verisiyle uyumlu olduğunu doğrular.
    ///
    /// # Errors
    /// Başlık meta veriyle uyuşmazsa `PacketError::Invalid` döner.
    pub fn ensure_matches(&self, header: &Header) -> Result<(), PacketError> {
        if self.version != header.version
            || self.profile != header.profile
            || self.calib_id != header.calib_id
            || self.coord_digest != header.coord_digest
            || self.salts != header.salts
            || self.kem != header.kem
            || self.algorithm != header.aead.alg
        {
            return Err(PacketError::Invalid("session metadata mismatch"));
        }
        Ok(())
    }

    /// Strict kip politikalarını doğrular.
    ///
    /// # Errors
    /// Strict kip etkin ve KEM bilgisi boş ise `PacketError::Strict` döner.
    pub fn ensure_strict(&self, strict: bool) -> Result<(), PacketError> {
        if strict && self.kem.kem == "none" {
            Err(PacketError::Strict("kem material required in strict mode"))
        } else {
            Ok(())
        }
    }
}

pub struct SessionEncryptParams<'a> {
    pub ratchet: &'a mut SessionRatchet,
    pub metadata: &'a SessionMetadata,
    pub plaintext: &'a [u8],
    pub aad: &'a [u8],
}

pub struct SessionDecryptParams<'a> {
    pub ratchet: &'a mut SessionRatchet,
    pub metadata: &'a SessionMetadata,
    pub store: &'a mut SessionStore,
    pub aad: &'a [u8],
    pub packet: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionStepOutcome {
    pub session_id: [u8; 16],
    pub message_no: u64,
}

#[derive(Default, Debug)]
pub struct SessionStore {
    seen: HashSet<([u8; 16], u64)>,
}

impl SessionStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, session_id: [u8; 16], message_no: u64) -> bool {
        self.seen.insert((session_id, message_no))
    }
}

/// Oturum ratchet'ı kullanarak şifreli paket üretir.
///
/// # Errors
/// Strict politika ihlali veya kriptografik işlemler başarısız olduğunda `PacketError` döner.
#[allow(clippy::needless_pass_by_value)]
pub fn encrypt_session(
    params: SessionEncryptParams<'_>,
) -> Result<(Packet, SessionStepOutcome), PacketError> {
    params.metadata.ensure_strict(params.ratchet.is_strict())?;
    let step = params.ratchet.next_step()?;
    let session_id = params.ratchet.session_id();

    let step_secret = Zeroizing::new(step.step_secret);
    let message_secret = Zeroizing::new(step.message_secret);
    let label = format!("{}:{}", params.metadata.calib_id, step.message_no);
    let step_key: &[u8; 32] = &step_secret;
    let message_key: &[u8; 32] = &message_secret;
    let keys = derive_keys(step_key, &label)?;
    let aad_digest_value = aad_digest(params.aad);

    let mut header = Header {
        version: params.metadata.version.clone(),
        profile: params.metadata.profile,
        calib_id: params.metadata.calib_id.clone(),
        coord_digest: params.metadata.coord_digest.clone(),
        salts: params.metadata.salts.clone(),
        kem: params.metadata.kem.clone(),
        aead: HeaderAead {
            alg: params.metadata.algorithm,
            nonce: base64_encode(&step.nonce),
            aad_digest: aad_digest_value,
        },
        session: Some(HeaderSession {
            id: base64_encode(&session_id),
            message_no: step.message_no,
            new: step.message_no == 0,
        }),
        sizes: HeaderSizes {
            plaintext: params.plaintext.len(),
            ciphertext: 0,
        },
        hdrmac: String::new(),
    };

    let ciphertext = crate::crypto::encrypt_aead(
        params.metadata.algorithm,
        message_key,
        &step.nonce,
        params.plaintext,
        params.aad,
    )?;

    header.sizes.ciphertext = ciphertext.len();
    header.hdrmac = compute_header_mac(&header, &keys.header_mac)?;
    let body_pmac = compute_body_pmac(&keys.body_mac, &ciphertext)?;

    let packet = Packet {
        header,
        ciphertext,
        body_pmac,
    };

    Ok((
        packet,
        SessionStepOutcome {
            session_id,
            message_no: step.message_no,
        },
    ))
}

/// Şifreli oturum paketini çözer ve ratchet durumunu ilerletir.
///
/// # Errors
/// Başlık doğrulamaları, bütünlük kontrolleri veya ratchet politikaları başarısız olursa
/// `PacketError` döner.
#[allow(clippy::needless_pass_by_value)]
pub fn decrypt_session(
    params: SessionDecryptParams<'_>,
) -> Result<(DecryptOk, SessionStepOutcome), PacketError> {
    params.metadata.ensure_strict(params.ratchet.is_strict())?;
    let packet = Packet::from_base64(params.packet)?;
    let session_header = packet
        .header
        .session
        .as_ref()
        .ok_or(PacketError::Invalid("missing session header"))?;
    params.metadata.ensure_matches(&packet.header)?;

    let expected_session = base64_encode(&params.ratchet.session_id());
    if session_header.id != expected_session {
        return Err(PacketError::Invalid("session id mismatch"));
    }
    if session_header.message_no != params.ratchet.message_no() {
        return Err(PacketError::Invalid("unexpected message number"));
    }
    if !params
        .store
        .register(params.ratchet.session_id(), session_header.message_no)
    {
        return Err(PacketError::Replay);
    }

    let aad_digest_value = aad_digest(params.aad);
    if packet.header.aead.aad_digest != aad_digest_value {
        return Err(PacketError::Invalid("aad mismatch"));
    }

    let step = params.ratchet.next_step()?;
    if base64_encode(&step.nonce) != packet.header.aead.nonce {
        return Err(PacketError::Integrity("nonce mismatch"));
    }
    let label = format!("{}:{}", params.metadata.calib_id, step.message_no);
    let step_secret = Zeroizing::new(step.step_secret);
    let message_secret = Zeroizing::new(step.message_secret);
    let step_key: &[u8; 32] = &step_secret;
    let message_key: &[u8; 32] = &message_secret;
    let keys = derive_keys(step_key, &label)?;

    verify_header_mac(&packet.header, &keys.header_mac)?;
    verify_body_pmac(&keys.body_mac, &packet.ciphertext, &packet.body_pmac)?;

    let plaintext = decrypt_aead(
        params.metadata.algorithm,
        message_key,
        &step.nonce,
        &packet.ciphertext,
        params.aad,
    )?;

    if plaintext.len() != packet.header.sizes.plaintext {
        return Err(PacketError::Integrity("plaintext size mismatch"));
    }

    let coord_id = params
        .metadata
        .coord_id
        .clone()
        .ok_or(PacketError::Invalid("coord id unavailable"))?;
    let coord = params
        .metadata
        .coord
        .ok_or(PacketError::Invalid("coord unavailable"))?;

    let metadata = params.metadata.clone();

    Ok((
        DecryptOk {
            plaintext,
            header: packet.header,
            coord_id,
            coord,
            metadata,
        },
        SessionStepOutcome {
            session_id: params.ratchet.session_id(),
            message_no: step.message_no,
        },
    ))
}
