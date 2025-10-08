use sha2::{Digest, Sha256};

/// Hesaplanan public anahtar özetinden deterministik `kid` üretir.
#[must_use]
pub fn compute_kid(public: &[u8; 32]) -> String {
    let digest = Sha256::digest(public);
    hex::encode(digest)
}
