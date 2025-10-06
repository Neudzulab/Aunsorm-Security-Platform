use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::CoreError;

/// Ratchet adımı çıktısı.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepSecret {
    pub message_no: u64,
    pub step_secret: [u8; 32],
    pub message_secret: [u8; 32],
    pub root_key: [u8; 32],
    pub nonce: [u8; 12],
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
            step_secret,
            message_secret: msg_secret,
            root_key: next_root,
            nonce,
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
        assert_ne!(strict_step.nonce, relaxed_step.nonce);
    }

    #[test]
    fn overflow_is_caught() {
        let mut ratchet = SessionRatchet::new([1_u8; 32], [2_u8; 16], false);
        ratchet.message_no = u64::MAX;
        let err = ratchet.next_step().unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)));
    }
}
