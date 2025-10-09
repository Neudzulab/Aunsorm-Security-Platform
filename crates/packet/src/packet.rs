use serde::{Deserialize, Serialize};

use aunsorm_core::{
    calibration::Calibration, derive_seed64_and_pdk, kdf::KdfProfile, salts::Salts,
};

use crate::crypto::{
    aad_digest, base64_decode, base64_encode, coord_digest, derive_keys, encrypt_aead,
    verify_body_pmac, verify_header_mac, KeyMaterial, VERSION,
};
use crate::error::PacketError;
use crate::header::{
    AeadAlgorithm, Header, HeaderAead, HeaderKem, HeaderProfile, HeaderSalts, HeaderSizes,
};
use crate::session::SessionMetadata;

/// Tek-atım şifreleme parametreleri.
pub struct EncryptParams<'a> {
    pub password: &'a str,
    pub password_salt: &'a [u8],
    pub calibration: &'a Calibration,
    pub salts: &'a Salts,
    pub plaintext: &'a [u8],
    pub aad: &'a [u8],
    pub profile: KdfProfile,
    pub algorithm: AeadAlgorithm,
    pub strict: bool,
    pub kem: Option<KemPayload<'a>>,
}

/// KEM malzemesi.
pub struct KemPayload<'a> {
    pub kem: &'a str,
    pub pk: Option<&'a [u8]>,
    pub ctkem: Option<&'a [u8]>,
    pub rbkem: Option<&'a [u8]>,
    pub ss: Option<&'a [u8]>,
}

/// Tek-atım deşifre parametreleri.
pub struct DecryptParams<'a> {
    pub password: &'a str,
    pub password_salt: &'a [u8],
    pub calibration: &'a Calibration,
    pub salts: &'a Salts,
    pub profile: KdfProfile,
    pub aad: &'a [u8],
    pub strict: bool,
    pub packet: &'a str,
}

/// Deşifre çıktısı.
#[derive(Debug)]
pub struct DecryptOk {
    pub plaintext: Vec<u8>,
    pub header: Header,
    pub coord_id: String,
    pub coord: [u8; 32],
    pub metadata: SessionMetadata,
}

#[derive(Serialize, Deserialize)]
struct WirePacket {
    header: Header,
    body: WireBody,
}

#[derive(Serialize, Deserialize)]
struct WireBody {
    ciphertext: String,
    pmac: String,
}

/// Şifrelenmiş paketi temsil eder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub header: Header,
    pub ciphertext: Vec<u8>,
    pub body_pmac: [u8; 16],
}

impl Packet {
    /// Paket verisini Base64 olarak serileştirir.
    ///
    /// # Errors
    /// Serileştirme sırasında JSON üretimi başarısız olursa `PacketError::Serialization` döner.
    pub fn to_base64(&self) -> Result<String, PacketError> {
        let wire = WirePacket {
            header: self.header.clone(),
            body: WireBody {
                ciphertext: base64_encode(&self.ciphertext),
                pmac: base64_encode(&self.body_pmac),
            },
        };
        let json = serde_json::to_vec(&wire)?;
        Ok(base64_encode(&json))
    }

    /// Base64 kodlu paket verisinden `Packet` örneği oluşturur.
    ///
    /// # Errors
    /// Veriler geçersiz Base64 içeriyorsa veya JSON ayrıştırma başarısız olursa `PacketError`
    /// döner.
    pub fn from_base64(encoded: &str) -> Result<Self, PacketError> {
        let data = base64_decode(encoded)?;
        let wire: WirePacket = serde_json::from_slice(&data)?;
        let ciphertext = base64_decode(&wire.body.ciphertext)?;
        let pmac_bytes = base64_decode(&wire.body.pmac)?;
        let mut pmac = [0_u8; 16];
        if pmac_bytes.len() != 16 {
            return Err(PacketError::Invalid("pmac must be 16 bytes"));
        }
        pmac.copy_from_slice(&pmac_bytes);
        Ok(Self {
            header: wire.header,
            ciphertext,
            body_pmac: pmac,
        })
    }
}

fn build_kem(payload: Option<KemPayload<'_>>) -> HeaderKem {
    payload.map_or_else(HeaderKem::none, |kem| HeaderKem {
        kem: kem.kem.to_owned(),
        pk: kem.pk.map(base64_encode),
        ctkem: kem.ctkem.map(base64_encode),
        rbkem: kem.rbkem.map(base64_encode),
        ss: kem.ss.map(base64_encode),
    })
}

fn derive_material(
    password: &str,
    password_salt: &[u8],
    salts: &Salts,
    profile: KdfProfile,
    calibration: &Calibration,
) -> Result<(String, [u8; 32], KeyMaterial), PacketError> {
    let (seed, pdk, _) = derive_seed64_and_pdk(
        password,
        password_salt,
        salts.calibration(),
        salts.chain(),
        profile,
    )?;
    let (coord_id, coord) = aunsorm_core::coord32_derive(seed.as_ref(), calibration, salts)?;
    let keys = derive_keys(pdk.as_ref(), calibration.id.as_str())?;
    Ok((coord_id, coord, keys))
}

fn ensure_strict(kem: &HeaderKem, strict: bool) -> Result<(), PacketError> {
    if strict && kem.kem == "none" {
        Err(PacketError::Strict("kem material required in strict mode"))
    } else {
        Ok(())
    }
}

/// Verilen bağlamla tek seferlik şifreli paket üretir.
///
/// # Errors
/// Salt doğrulaması, strict politikalar veya kriptografik işlemler başarısız olursa `PacketError`
/// döner.
pub fn encrypt_one_shot(params: EncryptParams<'_>) -> Result<Packet, PacketError> {
    let kem = build_kem(params.kem);
    ensure_strict(&kem, params.strict)?;

    let (_coord_id, coord, keys) = derive_material(
        params.password,
        params.password_salt,
        params.salts,
        params.profile,
        params.calibration,
    )?;
    let nonce = crate::crypto::generate_nonce(params.algorithm);
    let aad_digest_value = aad_digest(params.aad);

    let mut header = Header {
        version: VERSION.to_string(),
        profile: HeaderProfile::from(params.profile),
        calib_id: params.calibration.id.as_str().to_owned(),
        coord_digest: coord_digest(&coord),
        salts: HeaderSalts::from_bytes(params.password_salt, params.salts),
        kem,
        aead: HeaderAead {
            alg: params.algorithm,
            nonce: base64_encode(&nonce),
            aad_digest: aad_digest_value,
        },
        session: None,
        sizes: HeaderSizes {
            plaintext: params.plaintext.len(),
            ciphertext: 0,
        },
        hdrmac: String::new(),
    };

    let ciphertext = encrypt_aead(
        params.algorithm,
        &keys.aead,
        &nonce,
        params.plaintext,
        params.aad,
    )?;

    header.sizes.ciphertext = ciphertext.len();
    header.hdrmac = crate::crypto::compute_header_mac(&header, &keys.header_mac)?;
    let body_pmac = crate::crypto::compute_body_pmac(&keys.body_mac, &ciphertext)?;

    Ok(Packet {
        header,
        ciphertext,
        body_pmac,
    })
}

/// Tek-atım paketi çözer ve kalibrasyon bağlamını doğrular.
///
/// # Errors
/// Strict politika ihlalleri, bütünlük kontrolleri veya AEAD çözme hataları durumunda `PacketError`
/// döner.
pub fn decrypt_one_shot(params: &DecryptParams<'_>) -> Result<DecryptOk, PacketError> {
    let packet = Packet::from_base64(params.packet)?;
    if packet.header.version != VERSION {
        return Err(PacketError::Invalid("unsupported packet version"));
    }
    if packet.header.session.is_some() {
        return Err(PacketError::Invalid(
            "session field present in one-shot packet",
        ));
    }
    if !packet
        .header
        .salts
        .matches(params.password_salt, params.salts)
    {
        return Err(PacketError::Invalid("salt mismatch"));
    }
    if !packet.header.profile.matches_profile(&params.profile) {
        return Err(PacketError::Invalid("profile mismatch"));
    }
    ensure_strict(&packet.header.kem, params.strict)?;

    let (coord_id, coord, keys) = derive_material(
        params.password,
        params.password_salt,
        params.salts,
        params.profile,
        params.calibration,
    )?;

    if packet.header.coord_digest != coord_digest(&coord) {
        return Err(PacketError::Integrity("coord digest mismatch"));
    }

    let aad_digest_value = aad_digest(params.aad);
    if packet.header.aead.aad_digest != aad_digest_value {
        return Err(PacketError::Invalid("aad mismatch"));
    }

    verify_header_mac(&packet.header, &keys.header_mac)?;
    verify_body_pmac(&keys.body_mac, &packet.ciphertext, &packet.body_pmac)?;

    let nonce_bytes = base64_decode(&packet.header.aead.nonce)?;
    let expected_len = crate::crypto::nonce_length(packet.header.aead.alg);
    if nonce_bytes.len() != expected_len {
        return Err(PacketError::Invalid("nonce length invalid"));
    }

    let plaintext = crate::crypto::decrypt_aead(
        packet.header.aead.alg,
        &keys.aead,
        &nonce_bytes,
        &packet.ciphertext,
        params.aad,
    )?;

    if plaintext.len() != packet.header.sizes.plaintext {
        return Err(PacketError::Integrity("plaintext size mismatch"));
    }

    let metadata = SessionMetadata::from_header(&packet.header).with_coord(coord_id.clone(), coord);

    Ok(DecryptOk {
        plaintext,
        header: packet.header,
        coord_id,
        coord,
        metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aunsorm_core::session::SessionRatchet;
    use aunsorm_core::{calibration::calib_from_text, salts::Salts, KdfPreset, KdfProfile};

    use crate::{
        decrypt_session, encrypt_session, peek_header, SessionDecryptParams, SessionEncryptParams,
        SessionStore,
    };

    const PASSWORD: &str = "correct horse battery staple";

    fn test_salts() -> Salts {
        Salts::new(
            b"calib-salt-12345".to_vec(),
            b"chain-salt-54321".to_vec(),
            b"coord-salt-11111".to_vec(),
        )
        .expect("salts")
    }

    #[test]
    fn one_shot_roundtrip() {
        let profile = KdfProfile::preset(KdfPreset::Low);
        let salts = test_salts();
        let (calibration, _) = calib_from_text(b"org", "note");
        let password_salt = b"password-salt-888";
        let packet = encrypt_one_shot(EncryptParams {
            password: PASSWORD,
            password_salt,
            calibration: &calibration,
            salts: &salts,
            plaintext: b"super secret",
            aad: b"meta",
            profile,
            algorithm: AeadAlgorithm::AesGcm,
            strict: false,
            kem: None,
        })
        .expect("encrypt");

        let encoded = packet.to_base64().expect("encode");
        let decrypt_params = DecryptParams {
            password: PASSWORD,
            password_salt,
            calibration: &calibration,
            salts: &salts,
            profile,
            aad: b"meta",
            strict: false,
            packet: &encoded,
        };
        let decrypted = decrypt_one_shot(&decrypt_params).expect("decrypt");

        assert_eq!(decrypted.plaintext, b"super secret");
        assert!(decrypted.metadata.coord_id.is_some());
        assert!(decrypted.metadata.coord.is_some());

        let header = peek_header(&encoded).expect("peek");
        assert_eq!(header.calib_id, decrypted.header.calib_id);
    }

    #[test]
    fn strict_mode_accepts_pqc_payload() {
        if !aunsorm_pqc::kem::KemAlgorithm::MlKem768.is_available() {
            return;
        }

        let profile = KdfProfile::preset(KdfPreset::Low);
        let salts = test_salts();
        let (calibration, _) = calib_from_text(b"org", "strict-note");
        let password_salt = b"password-salt-999";

        let kem_keys =
            aunsorm_pqc::kem::KemKeyPair::generate(aunsorm_pqc::kem::KemAlgorithm::MlKem768)
                .expect("kem keypair");
        let kem_bundle = aunsorm_pqc::kem::encapsulate(
            aunsorm_pqc::kem::KemAlgorithm::MlKem768,
            kem_keys.public_key(),
        )
        .expect("encapsulate");
        let kem_payload = kem_bundle.packet_payload(kem_keys.public_key());
        let kem = KemPayload {
            kem: kem_payload.kem,
            pk: kem_payload.public_key,
            ctkem: kem_payload.ciphertext,
            rbkem: kem_payload.responder_key,
            ss: kem_payload.shared_secret,
        };

        let packet = encrypt_one_shot(EncryptParams {
            password: PASSWORD,
            password_salt,
            calibration: &calibration,
            salts: &salts,
            plaintext: b"strict secret",
            aad: b"meta",
            profile,
            algorithm: AeadAlgorithm::AesGcm,
            strict: true,
            kem: Some(kem),
        })
        .expect("strict encrypt");

        let encoded = packet.to_base64().expect("encode");
        let decrypt_params = DecryptParams {
            password: PASSWORD,
            password_salt,
            calibration: &calibration,
            salts: &salts,
            profile,
            aad: b"meta",
            strict: true,
            packet: &encoded,
        };
        let decrypted = decrypt_one_shot(&decrypt_params).expect("decrypt");
        assert_eq!(decrypted.plaintext, b"strict secret");
    }

    #[test]
    fn decrypt_rejects_wrong_calibration() {
        let profile = KdfProfile::preset(KdfPreset::Low);
        let salts = test_salts();
        let (calibration, _) = calib_from_text(b"org", "note");
        let password_salt = b"password-salt-888";
        let packet = encrypt_one_shot(EncryptParams {
            password: PASSWORD,
            password_salt,
            calibration: &calibration,
            salts: &salts,
            plaintext: b"super secret",
            aad: b"meta",
            profile,
            algorithm: AeadAlgorithm::AesGcm,
            strict: false,
            kem: None,
        })
        .expect("encrypt");
        let encoded = packet.to_base64().expect("encode");

        let (wrong_calibration, _) = calib_from_text(b"org", "wrong-note");
        let wrong_params = DecryptParams {
            password: PASSWORD,
            password_salt,
            calibration: &wrong_calibration,
            salts: &salts,
            profile,
            aad: b"meta",
            strict: false,
            packet: &encoded,
        };
        let err = decrypt_one_shot(&wrong_params).expect_err("should fail");

        assert!(matches!(err, PacketError::Integrity(_)));
    }

    #[cfg(feature = "aes-siv")]
    #[test]
    fn aes_siv_roundtrip() {
        let profile = KdfProfile::preset(KdfPreset::Low);
        let salts = test_salts();
        let (calibration, _) = calib_from_text(b"org", "siv-note");
        let password_salt = b"password-salt-siv";
        let packet = encrypt_one_shot(EncryptParams {
            password: PASSWORD,
            password_salt,
            calibration: &calibration,
            salts: &salts,
            plaintext: b"aes-siv secret",
            aad: b"meta",
            profile,
            algorithm: AeadAlgorithm::AesSiv,
            strict: false,
            kem: None,
        })
        .expect("encrypt");

        let encoded = packet.to_base64().expect("encode");
        let decrypt_params = DecryptParams {
            password: PASSWORD,
            password_salt,
            calibration: &calibration,
            salts: &salts,
            profile,
            aad: b"meta",
            strict: false,
            packet: &encoded,
        };
        let decrypted = decrypt_one_shot(&decrypt_params).expect("decrypt");

        assert_eq!(decrypted.plaintext, b"aes-siv secret");
        assert_eq!(decrypted.header.aead.alg, AeadAlgorithm::AesSiv);
    }

    #[test]
    fn session_roundtrip() {
        let profile = KdfProfile::preset(KdfPreset::Low);
        let salts = test_salts();
        let (calibration, _) = calib_from_text(b"org", "session-note");
        let password_salt = b"password-salt-888";
        let bootstrap = encrypt_one_shot(EncryptParams {
            password: PASSWORD,
            password_salt,
            calibration: &calibration,
            salts: &salts,
            plaintext: b"bootstrap",
            aad: b"meta",
            profile,
            algorithm: AeadAlgorithm::Chacha20Poly1305,
            strict: false,
            kem: None,
        })
        .expect("encrypt");
        let encoded = bootstrap.to_base64().expect("encode");
        let bootstrap_params = DecryptParams {
            password: PASSWORD,
            password_salt,
            calibration: &calibration,
            salts: &salts,
            profile,
            aad: b"meta",
            strict: false,
            packet: &encoded,
        };
        let bootstrap_ok = decrypt_one_shot(&bootstrap_params).expect("decrypt");

        let metadata = bootstrap_ok.metadata;
        let sender_root = [7_u8; 32];
        let receiver_root = [7_u8; 32];
        let session_id = [9_u8; 16];
        let mut sender = SessionRatchet::new(sender_root, session_id, false);
        let mut receiver = SessionRatchet::new(receiver_root, session_id, false);

        let encrypt_params = SessionEncryptParams {
            ratchet: &mut sender,
            metadata: &metadata,
            plaintext: b"session secret",
            aad: b"session aad",
        };
        let (packet, outcome) = encrypt_session(encrypt_params).expect("session encrypt");
        assert_eq!(outcome.message_no, 0);

        let encoded_session = packet.to_base64().expect("session encode");
        let mut store = SessionStore::new();
        let decrypt_params = SessionDecryptParams {
            ratchet: &mut receiver,
            metadata: &metadata,
            store: &mut store,
            aad: b"session aad",
            packet: &encoded_session,
        };
        let (decrypted, recv_outcome) = decrypt_session(decrypt_params).expect("session decrypt");

        assert_eq!(decrypted.plaintext, b"session secret");
        assert_eq!(recv_outcome.message_no, 0);

        let replay_params = SessionDecryptParams {
            ratchet: &mut receiver,
            metadata: &metadata,
            store: &mut store,
            aad: b"session aad",
            packet: &encoded_session,
        };
        let replay = decrypt_session(replay_params);
        assert!(matches!(
            replay,
            Err(PacketError::Replay | PacketError::Invalid(_))
        ));
    }
}
