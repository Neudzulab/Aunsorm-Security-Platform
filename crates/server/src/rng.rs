//! Native Aunsorm RNG implementation for the server crate.
//!
//! This module mirrors the entropy generation strategy that other Aunsorm
//! components use, ensuring that every random value produced inside the
//! server follows the HKDF + NEUDZ-PCS + AACM pipeline mandated by the
//! platform.

use hkdf::Hkdf;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::hash_map::DefaultHasher;
use std::convert::TryFrom;
use std::hash::{Hash, Hasher};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Native RNG used by the Aunsorm server.
///
/// This is a direct port of the production entropy pipeline, avoiding HTTP
/// round-trips while preserving the statistical properties expected by
/// downstream services.
#[derive(Debug)]
pub struct AunsormNativeRng {
    entropy_salt: [u8; 32],
    state: [u8; 32],
    counter: u64,
}

impl AunsormNativeRng {
    /// Create a new RNG seeded from the operating system entropy source.
    #[must_use]
    pub fn new() -> Self {
        let mut entropy_salt = [0u8; 32];
        OsRng.fill_bytes(&mut entropy_salt);

        let mut state = [0u8; 32];
        OsRng.fill_bytes(&mut state);

        Self {
            entropy_salt,
            state,
            counter: 0,
        }
    }

    /// Generate the next 32-byte entropy block using Aunsorm's mathematical
    /// mixing strategy.
    fn next_entropy_block(&mut self) -> [u8; 32] {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_nanos()
            .to_le_bytes();

        let counter = self.counter;
        self.counter = self.counter.wrapping_add(1);

        let process_id = std::process::id();

        let thread_id = std::thread::current().id();
        let thread_hash = {
            let mut hasher = DefaultHasher::new();
            thread_id.hash(&mut hasher);
            hasher.finish()
        };

        let hk = Hkdf::<Sha256>::new(Some(&self.entropy_salt), &self.state);
        let mut okm = [0u8; 32];

        let mut info = Vec::with_capacity(40);
        info.extend_from_slice(&counter.to_le_bytes());
        info.extend_from_slice(&timestamp);
        info.extend_from_slice(&process_id.to_le_bytes());
        info.extend_from_slice(&thread_hash.to_le_bytes());

        hk.expand(&info, &mut okm)
            .expect("HKDF expand with 32 bytes should never fail");

        Self::apply_mathematical_mixing(&mut okm);

        let mut hasher = Sha256::new();
        hasher.update(self.entropy_salt);
        hasher.update(self.state);
        hasher.update(&info);
        hasher.update(okm);
        self.state.copy_from_slice(&hasher.finalize());

        okm
    }

    /// NEUDZ-PCS entropy mixing based on the prime counting function.
    #[allow(clippy::suboptimal_flops)]
    fn neudz_pcs_mix(x: f64) -> f64 {
        if x <= 1.0 {
            return x;
        }
        let ln_x = x.ln();
        let pi_approx = x / ln_x;
        let mertens_approx = if x >= 2.0 {
            let sqrt_x = x.sqrt();
            pi_approx - (2.0 * sqrt_x / ln_x)
        } else {
            pi_approx
        };
        (mertens_approx % 256.0).abs()
    }

    /// Apply prime-distribution and angular correction mixing to entropy
    /// bytes in-place.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss,
        clippy::suboptimal_flops
    )]
    fn apply_mathematical_mixing(entropy: &mut [u8; 32]) {
        for (i, byte) in entropy.iter_mut().enumerate() {
            let idx = f64::from(u32::try_from(i).expect("entropy index < 2^32"));
            let x = idx.mul_add(0.618_033_988_749, f64::from(*byte));
            let mixed = Self::neudz_pcs_mix(x + 1.0);
            *byte = byte.wrapping_add(mixed as u8);
        }
    }
}

impl Default for AunsormNativeRng {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoRng for AunsormNativeRng {}

impl RngCore for AunsormNativeRng {
    fn next_u32(&mut self) -> u32 {
        let entropy = self.next_entropy_block();
        u32::from_le_bytes([entropy[0], entropy[1], entropy[2], entropy[3]])
    }

    fn next_u64(&mut self) -> u64 {
        let entropy = self.next_entropy_block();
        u64::from_le_bytes([
            entropy[0], entropy[1], entropy[2], entropy[3], entropy[4], entropy[5], entropy[6],
            entropy[7],
        ])
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0;
        while offset < dest.len() {
            let entropy = self.next_entropy_block();
            let remaining = dest.len() - offset;
            let chunk_size = std::cmp::min(32, remaining);
            dest[offset..offset + chunk_size].copy_from_slice(&entropy[..chunk_size]);
            offset += chunk_size;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// Convenience helper to construct a new RNG instance.
#[must_use]
pub fn create_aunsorm_rng() -> AunsormNativeRng {
    AunsormNativeRng::new()
}

#[cfg(test)]
mod tests {
    use super::AunsormNativeRng;
    use rand_core::RngCore;

    fn approx_eq(left: f64, right: f64) -> bool {
        (left - right).abs() < 1.0e-9
    }

    #[test]
    fn neudz_pcs_mix_matches_reference_values() {
        let cases = [
            (0.5, 0.5),
            (1.0, 1.0),
            (2.0, 1.195_167_704_609_232),
            (10.0, 1.596_225_342_918_410_1),
            (256.0, 40.395_461_144_890_97),
            (1000.0, 135.609_095_714_036_93),
        ];

        for (input, expected) in cases {
            let actual = AunsormNativeRng::neudz_pcs_mix(input);
            assert!(
                approx_eq(actual, expected),
                "unexpected mix for {input}: {actual} vs {expected}"
            );
        }
    }

    #[test]
    fn apply_mathematical_mixing_transforms_entropy() {
        let mut entropy = [0u8; 32];
        AunsormNativeRng::apply_mathematical_mixing(&mut entropy);

        let expected = [
            1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3,
            3, 3, 3, 3,
        ];

        assert_eq!(entropy, expected);
    }

    #[test]
    fn fill_bytes_populates_destination_buffer() {
        let mut rng = AunsormNativeRng::new();
        let mut buf = [0u8; 96];
        rng.fill_bytes(&mut buf);

        assert!(buf.iter().any(|&byte| byte != 0), "entropy block should not be all zeros");
    }

    #[test]
    fn try_fill_bytes_reports_success() {
        let mut rng = AunsormNativeRng::new();
        let mut buf = [0u8; 32];
        rng.try_fill_bytes(&mut buf).expect("try_fill_bytes should succeed");

        assert!(buf.iter().any(|&byte| byte != 0));
    }
}
