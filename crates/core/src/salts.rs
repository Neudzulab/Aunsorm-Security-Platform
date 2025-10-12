use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CoreError;

/// KDF ve koordinat türetiminde kullanılan salt seti.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop,
)]
pub struct Salts {
    calibration: Vec<u8>,
    chain: Vec<u8>,
    coord: Vec<u8>,
}

impl Salts {
    /// Yeni bir salt seti oluşturur.
    ///
    /// # Errors
    /// Salt uzunlukları 8 bayttan kısa olduğunda `CoreError::SaltTooShort` döner.
    pub fn new(calibration: Vec<u8>, chain: Vec<u8>, coord: Vec<u8>) -> Result<Self, CoreError> {
        if calibration.len() < 8 {
            return Err(CoreError::salt_too_short(
                "calibration salt must be >= 8 bytes",
            ));
        }
        if chain.len() < 8 {
            return Err(CoreError::salt_too_short("chain salt must be >= 8 bytes"));
        }
        if coord.len() < 8 {
            return Err(CoreError::salt_too_short("coord salt must be >= 8 bytes"));
        }
        Ok(Self {
            calibration,
            chain,
            coord,
        })
    }

    /// Kalibrasyon tuzu.
    #[must_use]
    pub fn calibration(&self) -> &[u8] {
        &self.calibration
    }

    /// Zincir tuzu.
    #[must_use]
    pub fn chain(&self) -> &[u8] {
        &self.chain
    }

    /// Koordinat türetimi için kullanılan tuz.
    #[must_use]
    pub fn coord(&self) -> &[u8] {
        &self.coord
    }

    pub(crate) fn digest_for_coord(&self, calibration_id: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"Aunsorm/1.01/coord-salt");
        hasher.update(calibration_id.as_bytes());
        hasher.update(&self.calibration);
        hasher.update(&self.chain);
        hasher.update(&self.coord);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    #[test]
    fn rejects_short_salts() {
        assert!(Salts::new(vec![0; 7], vec![0; 8], vec![0; 8]).is_err());
        assert!(Salts::new(vec![0; 8], vec![0; 7], vec![0; 8]).is_err());
        assert!(Salts::new(vec![0; 8], vec![0; 8], vec![0; 7]).is_err());
    }

    #[test]
    fn digest_depends_on_inputs() {
        let salts_a = Salts::new(vec![1; 8], vec![2; 8], vec![3; 8]).unwrap();
        let salts_b = Salts::new(vec![1; 8], vec![2; 8], vec![4; 8]).unwrap();
        assert_ne!(
            salts_a.digest_for_coord("id"),
            salts_b.digest_for_coord("id")
        );
    }

    #[test]
    fn zeroize_wipes_memory() {
        let mut salts = Salts::new(vec![1; 8], vec![2; 8], vec![3; 8]).unwrap();
        salts.zeroize();
        assert!(salts.calibration().iter().all(|&byte| byte == 0));
        assert!(salts.chain().iter().all(|&byte| byte == 0));
        assert!(salts.coord().iter().all(|&byte| byte == 0));
    }
}
