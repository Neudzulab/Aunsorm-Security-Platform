//! Native Aunsorm RNG implementation for the CLI crate.
//!
//! This mirrors the production entropy pipeline (HKDF + NEUDZ-PCS + AACM)
//! that every other component in the suite uses. Keeping the CLI on the
//! same algorithm guarantees determinism across tests and avoids falling
//! back to the operating system RNG beyond the initial seeding step.

use hkdf::Hkdf;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::hash_map::DefaultHasher;
use std::convert::TryFrom;
use std::hash::{Hash, Hasher};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Native RNG used by the CLI when generating cryptographic material.
#[derive(Debug)]
pub struct AunsormNativeRng {
    entropy_salt: [u8; 32],
    state: [u8; 32],
    counter: u64,
    cached_entropy: [u8; 32],
    cache_offset: usize,
}

impl AunsormNativeRng {
    /// Construct a new RNG instance seeded from the OS.
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
            cached_entropy: [0u8; 32],
            cache_offset: 32, // Force initial generation on first use
        }
    }

    /// Generate the next 32-byte entropy block using the mandated algorithm.
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

    /// Mathematical mixing step derived from NEUDZ-PCS and AACM research.
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
        if self.cache_offset + 4 <= 32 {
            let result = u32::from_le_bytes([
                self.cached_entropy[self.cache_offset],
                self.cached_entropy[self.cache_offset + 1],
                self.cached_entropy[self.cache_offset + 2],
                self.cached_entropy[self.cache_offset + 3],
            ]);
            self.cache_offset += 4;
            return result;
        }

        self.cached_entropy = self.next_entropy_block();
        self.cache_offset = 4;
        u32::from_le_bytes([
            self.cached_entropy[0],
            self.cached_entropy[1],
            self.cached_entropy[2],
            self.cached_entropy[3],
        ])
    }

    fn next_u64(&mut self) -> u64 {
        if self.cache_offset + 8 <= 32 {
            let result = u64::from_le_bytes([
                self.cached_entropy[self.cache_offset],
                self.cached_entropy[self.cache_offset + 1],
                self.cached_entropy[self.cache_offset + 2],
                self.cached_entropy[self.cache_offset + 3],
                self.cached_entropy[self.cache_offset + 4],
                self.cached_entropy[self.cache_offset + 5],
                self.cached_entropy[self.cache_offset + 6],
                self.cached_entropy[self.cache_offset + 7],
            ]);
            self.cache_offset += 8;
            return result;
        }

        self.cached_entropy = self.next_entropy_block();
        self.cache_offset = 8;
        u64::from_le_bytes([
            self.cached_entropy[0],
            self.cached_entropy[1],
            self.cached_entropy[2],
            self.cached_entropy[3],
            self.cached_entropy[4],
            self.cached_entropy[5],
            self.cached_entropy[6],
            self.cached_entropy[7],
        ])
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0;

        if self.cache_offset < 32 {
            let available = 32 - self.cache_offset;
            let to_copy = std::cmp::min(available, dest.len());
            dest[..to_copy].copy_from_slice(
                &self.cached_entropy[self.cache_offset..self.cache_offset + to_copy],
            );
            self.cache_offset += to_copy;
            offset += to_copy;
        }

        while offset < dest.len() {
            let entropy = self.next_entropy_block();
            let remaining = dest.len() - offset;
            let chunk_size = std::cmp::min(32, remaining);
            dest[offset..offset + chunk_size].copy_from_slice(&entropy[..chunk_size]);
            offset += chunk_size;

            if chunk_size < 32 {
                self.cached_entropy = entropy;
                self.cache_offset = chunk_size;
            }
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
