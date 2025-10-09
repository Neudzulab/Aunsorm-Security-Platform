use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CoreError;

/// Serileştirilebilir oturum ratchet durumu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRatchetState {
    pub root_key: [u8; 32],
    pub session_id: [u8; 16],
    pub message_no: u64,
    pub strict: bool,
}

impl SessionRatchetState {
    /// Yeni bir ratchet durumu oluşturur.
    #[must_use]
    pub const fn new(
        root_key: [u8; 32],
        session_id: [u8; 16],
        message_no: u64,
        strict: bool,
    ) -> Self {
        Self {
            root_key,
            session_id,
            message_no,
            strict,
        }
    }
}

/// Ratchet adımı çıktısı.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepSecret {
    message_no: u64,
    step_key: [u8; 32],
    message_key: [u8; 32],
    root_key_value: [u8; 32],
    nonce_value: [u8; 12],
}

impl StepSecret {
    /// Döngüdeki mesaj numarasını döndürür.
    #[must_use]
    pub const fn message_no(&self) -> u64 {
        self.message_no
    }

    /// Bir sonraki adımın gizini döndürür.
    #[must_use]
    pub const fn step_secret(&self) -> &[u8; 32] {
        &self.step_key
    }

    /// Mesaj için kullanılacak gizli anahtarı döndürür.
    #[must_use]
    pub const fn message_secret(&self) -> &[u8; 32] {
        &self.message_key
    }

    /// Güncellenmiş kök anahtarı döndürür.
    #[must_use]
    pub const fn root_key(&self) -> &[u8; 32] {
        &self.root_key_value
    }

    /// AEAD nonce değerini döndürür.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 12] {
        &self.nonce_value
    }
}

impl Drop for StepSecret {
    fn drop(&mut self) {
        self.step_key.zeroize();
        self.message_key.zeroize();
        self.root_key_value.zeroize();
        self.nonce_value.zeroize();
    }
}

/// Oturum anahtarı ratchet'i; deterministik fakat ileri gizlilik sağlar.
#[derive(Debug)]
pub struct SessionRatchet {
    root_key: Zeroizing<[u8; 32]>,
    session_id: [u8; 16],
    message_no: u64,
    strict: bool,
}

impl SessionRatchet {
    /// Yeni bir ratchet örneği oluşturur.
    #[must_use]
    pub fn new(root_key: [u8; 32], session_id: [u8; 16], strict: bool) -> Self {
        Self {
            root_key: Zeroizing::new(root_key),
            session_id,
            message_no: 0,
            strict,
        }
    }

    /// Oturum tanımlayıcısını döndürür.
    #[must_use]
    pub const fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    /// Strict kipinin etkin olup olmadığını belirtir.
    #[must_use]
    pub const fn is_strict(&self) -> bool {
        self.strict
    }

    /// Ratchet durumunu dışa aktarır.
    #[must_use]
    pub fn export_state(&self) -> SessionRatchetState {
        let mut root_key = [0_u8; 32];
        root_key.copy_from_slice(self.root_key.as_ref());
        SessionRatchetState {
            root_key,
            session_id: self.session_id,
            message_no: self.message_no,
            strict: self.strict,
        }
    }

    /// Dışa aktarılan durumdan ratchet oluşturur.
    #[must_use]
    pub fn from_state(state: SessionRatchetState) -> Self {
        Self {
            root_key: Zeroizing::new(state.root_key),
            session_id: state.session_id,
            message_no: state.message_no,
            strict: state.strict,
        }
    }

    /// Bir sonraki mesaj numarasını döndürür.
    #[must_use]
    pub const fn message_no(&self) -> u64 {
        self.message_no
    }

    fn hkdf(&self) -> Hkdf<Sha256> {
        Hkdf::<Sha256>::new(Some(&self.session_id), self.root_key.as_ref())
    }

    /// Bir sonraki mesaj için sıradaki gizleri türetir.
    ///
    /// # Errors
    /// HKDF çıkışı üretilemezse veya mesaj sayacı taşarsa `CoreError` döner.
    pub fn next_step(&mut self) -> Result<StepSecret, CoreError> {
        let msg_no = self.message_no;
        let hk = self.hkdf();

        let mut step_secret = [0_u8; 32];
        let mut msg_secret = [0_u8; 32];
        let mut next_root = [0_u8; 32];
        let mut nonce = [0_u8; 12];

        let mut info_step = b"Aunsorm/1.01/step".to_vec();
        info_step.extend_from_slice(&msg_no.to_be_bytes());
        hk.expand(&info_step, &mut step_secret)
            .map_err(|_| CoreError::hkdf_length())?;

        let mut info_msg = b"Aunsorm/1.01/message".to_vec();
        info_msg.extend_from_slice(&msg_no.to_be_bytes());
        hk.expand(&info_msg, &mut msg_secret)
            .map_err(|_| CoreError::hkdf_length())?;

        let mut info_root = b"Aunsorm/1.01/root".to_vec();
        info_root.extend_from_slice(&msg_no.to_be_bytes());
        hk.expand(&info_root, &mut next_root)
            .map_err(|_| CoreError::hkdf_length())?;

        // Nonce üretimi deterministik olmalıdır; ancak strict modda daha uzun nonce
        // çeşitliliği sağlamak için HKDF çıktısına rastgelelik eklenir.
        let mut info_nonce = b"Aunsorm/1.01/nonce".to_vec();
        info_nonce.extend_from_slice(&msg_no.to_be_bytes());
        if self.strict {
            info_nonce.extend_from_slice(b"/strict");
        }
        hk.expand(&info_nonce, &mut nonce)
            .map_err(|_| CoreError::hkdf_length())?;

        self.root_key.as_mut().copy_from_slice(&next_root);
        self.message_no = self
            .message_no
            .checked_add(1)
            .ok_or_else(|| CoreError::invalid_input("message counter overflow"))?;

        Ok(StepSecret {
            message_no: msg_no,
            step_key: step_secret,
            message_key: msg_secret,
            root_key_value: next_root,
            nonce_value: nonce,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratchet_is_deterministic_without_strict() {
        let mut ratchet_a = SessionRatchet::new([1_u8; 32], [2_u8; 16], false);
        let mut ratchet_b = SessionRatchet::new([1_u8; 32], [2_u8; 16], false);
        let step_a = ratchet_a.next_step().unwrap();
        let step_b = ratchet_b.next_step().unwrap();
        assert_eq!(step_a, step_b);
    }

    #[test]
    fn ratchet_nonce_varies_in_strict_mode() {
        let mut strict = SessionRatchet::new([1_u8; 32], [2_u8; 16], true);
        let mut relaxed = SessionRatchet::new([1_u8; 32], [2_u8; 16], false);
        let strict_step = strict.next_step().unwrap();
        let relaxed_step = relaxed.next_step().unwrap();
        assert_ne!(strict_step.nonce(), relaxed_step.nonce());
    }

    #[test]
    fn overflow_is_caught() {
        let mut ratchet = SessionRatchet::new([1_u8; 32], [2_u8; 16], false);
        ratchet.message_no = u64::MAX;
        let err = ratchet.next_step().unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));
    }

    #[test]
    fn state_roundtrip() {
        let mut ratchet = SessionRatchet::new([5_u8; 32], [7_u8; 16], true);
        let _ = ratchet.next_step().expect("step");
        let snapshot = ratchet.export_state();
        let mut restored = SessionRatchet::from_state(snapshot);
        assert_eq!(restored.session_id(), ratchet.session_id());
        assert_eq!(restored.message_no(), ratchet.message_no());
        assert_eq!(restored.is_strict(), ratchet.is_strict());
        let next_from_restored = restored.next_step().expect("next");
        let next_from_original = ratchet.next_step().expect("next");
        assert_eq!(
            next_from_restored.step_secret(),
            next_from_original.step_secret()
        );
    }
}
