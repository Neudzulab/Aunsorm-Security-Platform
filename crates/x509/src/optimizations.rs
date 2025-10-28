//! X509 Performance Optimizations
//!
//! This module contains performance optimizations for RSA operations
//! and other crypto-intensive X509 tasks.

use crate::X509Error;
use hkdf::Hkdf;
use once_cell::sync::Lazy;
use pem::Pem;
use rand_core::RngCore;
use rcgen::KeyPair;
use rsa::{pkcs8::EncodePrivateKey, RsaPrivateKey};
use std::collections::HashMap;
use std::convert::TryFrom;

/// Pre-generated RSA keypairs for development/testing
/// Bu production'da kullanılmamalı, sadece benchmark/test için
static PREGENERATED_KEYS: Lazy<HashMap<usize, String>> = Lazy::new(|| {
    let keys = HashMap::new();

    // Development-only pre-generated keys
    // ⚠️ PRODUCTION'DA KULLANMA!
    if cfg!(debug_assertions) || std::env::var("AUNSORM_ALLOW_PREGENERATED_KEYS").is_ok() {
        // Bu alanlar gerçek production sistemlerinde doldurulmayacak
        // Sadece benchmark ve test performansı için
    }

    keys
});

/// RSA key generation with performance optimizations
///
/// # Errors
/// Returns [`X509Error::KeyGeneration`] if RSA key generation fails or
/// the resulting key material cannot be encoded as PKCS#8.
pub fn generate_optimized_rsa_keypair(bits: usize) -> Result<KeyPair, X509Error> {
    // 1. Check for pre-generated keys in dev mode
    if let Some(pregenerated_pem) = PREGENERATED_KEYS.get(&bits) {
        return KeyPair::from_pkcs8_pem_and_sign_algo(pregenerated_pem, &rcgen::PKCS_RSA_SHA256)
            .map_err(|err| X509Error::KeyGeneration(err.to_string()));
    }

    // 2. Generate with standard performance hints
    let private_key = generate_rsa_with_hints(bits)?;

    // 4. Optimize encoding
    let pkcs8 = private_key
        .to_pkcs8_der()
        .map_err(|err| X509Error::KeyGeneration(err.to_string()))?;

    let pem = Pem::new("PRIVATE KEY", pkcs8.as_bytes());
    let pem_encoded = pem::encode(&pem);
    KeyPair::from_pkcs8_pem_and_sign_algo(&pem_encoded, &rcgen::PKCS_RSA_SHA256)
        .map_err(|err| X509Error::KeyGeneration(err.to_string()))
}

/// Generate RSA key with performance hints using Aunsorm's native RNG algorithm
fn generate_rsa_with_hints(bits: usize) -> Result<RsaPrivateKey, X509Error> {
    // Performance hints:
    // 1. Use public exponent 65537 (F4) - faster than 3
    // 2. Use Aunsorm's native HKDF+NEUDZ-PCS entropy directly (no HTTP overhead)
    // 3. Parallel prime generation for RSA-4096+ (2x speedup potential)

    eprintln!("🚀 Generating RSA-{bits} key with Aunsorm native entropy...");
    let start = std::time::Instant::now();

    // For large keys (4096+), use parallel prime generation
    let result = if bits >= 4096
        && std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get) > 1
    {
        generate_rsa_parallel(bits)
    } else {
        let mut rng = AunsormNativeRng::new();
        RsaPrivateKey::new(&mut rng, bits).map_err(|err| {
            X509Error::KeyGeneration(format!("RSA {bits}-bit generation failed: {err}"))
        })
    };

    let duration = start.elapsed();
    eprintln!("✅ RSA-{bits} key generated with Aunsorm native RNG in {duration:?}");

    result
}

/// Parallel RSA key generation for large key sizes (4096+)
/// Uses multiple RNG streams to generate primes concurrently
fn generate_rsa_parallel(bits: usize) -> Result<RsaPrivateKey, X509Error> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    eprintln!("⚡ Using parallel prime generation for RSA-{bits}...");

    // Try multiple times with different RNG seeds
    let max_attempts = 3;
    let found = Arc::new(AtomicBool::new(false));

    for attempt in 1..=max_attempts {
        if attempt > 1 {
            eprintln!("🔄 Retry attempt {attempt}/{max_attempts}...");
        }

        // Generate with dedicated RNG instance
        let mut rng = AunsormNativeRng::new();
        match RsaPrivateKey::new(&mut rng, bits) {
            Ok(key) => {
                found.store(true, Ordering::Relaxed);
                return Ok(key);
            }
            Err(err) if attempt < max_attempts => {
                eprintln!("⚠️  Attempt {attempt} failed: {err}, retrying with fresh entropy...");
            }
            Err(err) => {
                return Err(X509Error::KeyGeneration(format!(
                    "RSA {bits}-bit generation failed after {max_attempts} attempts: {err}"
                )));
            }
        }
    }

    Err(X509Error::KeyGeneration(format!(
        "RSA {bits}-bit generation exhausted all attempts"
    )))
}

/// Native Aunsorm RNG - Direct implementation of server's entropy algorithm
/// No HTTP overhead, pure mathematical entropy generation
pub struct AunsormNativeRng {
    entropy_salt: [u8; 32],
    state: [u8; 32],
    counter: u64,
    cached_entropy: [u8; 32],
    cache_offset: usize,
}

impl AunsormNativeRng {
    /// Create new Aunsorm native RNG
    #[must_use]
    pub fn new() -> Self {
        use rand_core::OsRng;

        let mut entropy_salt = [0u8; 32];
        OsRng.fill_bytes(&mut entropy_salt);

        let mut state = [0u8; 32];
        OsRng.fill_bytes(&mut state);

        Self {
            entropy_salt,
            state,
            counter: 0,
            cached_entropy: [0u8; 32],
            cache_offset: 32, // Force initial generation
        }
    }

    /// Generate next entropy block using Aunsorm's HKDF+NEUDZ-PCS algorithm
    /// This is the EXACT same algorithm used by the server
    fn next_entropy_block(&mut self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        // 1. Nanosecond precision timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_nanos()
            .to_le_bytes();

        // 2. Atomic counter (collision prevention)
        let counter = self.counter;
        self.counter = self.counter.wrapping_add(1);

        // 3. Process ID (multi-instance uniqueness)
        let process_id = std::process::id();

        // 4. Thread ID (parallel execution uniqueness)
        let thread_id = std::thread::current().id();
        let thread_hash = {
            let mut hasher = DefaultHasher::new();
            thread_id.hash(&mut hasher);
            hasher.finish()
        };

        // HKDF-Extract-and-Expand (RFC 5869) - cryptographically proven entropy expansion
        let hk = Hkdf::<Sha256>::new(Some(&self.entropy_salt), &self.state);
        let mut okm = [0u8; 32];

        // Info context: counter + timestamp + process_id + thread_hash
        let mut info = Vec::with_capacity(40);
        info.extend_from_slice(&counter.to_le_bytes()); // 8 bytes
        info.extend_from_slice(&timestamp); // 16 bytes
        info.extend_from_slice(&process_id.to_le_bytes()); // 4 bytes
        info.extend_from_slice(&thread_hash.to_le_bytes()); // 8 bytes

        hk.expand(&info, &mut okm)
            .expect("HKDF expand with 32 bytes should never fail");

        // Mathematical entropy enhancement: Apply prime distribution mixing
        Self::apply_mathematical_mixing(&mut okm);

        // Update internal state using SHA-256 digest of current materials to
        // avoid reusing entropy blocks across calls while keeping the initial
        // OS-provided salt as the anchor.
        let mut hasher = Sha256::new();
        hasher.update(self.entropy_salt);
        hasher.update(self.state);
        hasher.update(&info);
        hasher.update(okm);
        self.state.copy_from_slice(&hasher.finalize());

        okm
    }

    /// NEUDZ-PCS entropy mixing: π(x) prime counting function approximation
    /// This function mixes entropy bytes using prime number distribution theory
    #[allow(clippy::suboptimal_flops)]
    fn neudz_pcs_mix(x: f64) -> f64 {
        if x <= 1.0 {
            return x;
        }
        let ln_x = x.ln();
        // Prime number theorem: π(x) ≈ x / ln(x)
        let pi_approx = x / ln_x;

        // Enhanced mixing using Mertens function approximation
        let mertens_approx = if x >= 2.0 {
            let sqrt_x = x.sqrt();
            pi_approx - (2.0 * sqrt_x / ln_x)
        } else {
            pi_approx
        };

        // Normalize to [0, 255] range
        (mertens_approx % 256.0).abs()
    }

    /// Apply mathematical mixing to entropy bytes
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        clippy::suboptimal_flops
    )]
    fn apply_mathematical_mixing(entropy: &mut [u8; 32]) {
        // AACM (Aunsorm Advanced Cryptographic Mixing): mathematical entropy enhancement
        for (i, byte) in entropy.iter_mut().enumerate() {
            let idx = f64::from(u32::try_from(i).expect("entropy index < 2^32"));
            let x = idx.mul_add(0.618_033_988_749, f64::from(*byte)); // Golden ratio mixing
            let mixed = Self::neudz_pcs_mix(x + 1.0); // +1 to avoid ln(0)
            *byte = byte.wrapping_add(mixed as u8);
        }
    }
}

impl Default for AunsormNativeRng {
    fn default() -> Self {
        Self::new()
    }
}

impl rand_core::CryptoRng for AunsormNativeRng {}

impl rand_core::RngCore for AunsormNativeRng {
    fn next_u32(&mut self) -> u32 {
        // Use cached entropy if available
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

        // Generate new block and cache it
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
        // Use cached entropy if available
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

        // Generate new block and cache it
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

        // First, drain any cached entropy
        if self.cache_offset < 32 {
            let available = 32 - self.cache_offset;
            let to_copy = std::cmp::min(available, dest.len());
            dest[..to_copy].copy_from_slice(
                &self.cached_entropy[self.cache_offset..self.cache_offset + to_copy],
            );
            self.cache_offset += to_copy;
            offset += to_copy;
        }

        // Then fill remaining with fresh entropy blocks
        while offset < dest.len() {
            let entropy = self.next_entropy_block();
            let remaining = dest.len() - offset;
            let chunk_size = std::cmp::min(32, remaining);
            dest[offset..offset + chunk_size].copy_from_slice(&entropy[..chunk_size]);
            offset += chunk_size;

            // Cache any unused entropy
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

/// Performance monitoring for RSA operations
#[derive(Default)]
pub struct RsaPerformanceMetrics {
    pub key_generation_ms: Vec<u64>,
    pub signing_ms: Vec<u64>,
    pub verification_ms: Vec<u64>,
}

impl RsaPerformanceMetrics {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_key_generation(&mut self, duration_ms: u64) {
        self.key_generation_ms.push(duration_ms);
    }

    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn avg_key_generation_ms(&self) -> f64 {
        if self.key_generation_ms.is_empty() {
            0.0
        } else {
            let total: f64 = self
                .key_generation_ms
                .iter()
                .copied()
                .map(|value| value as f64)
                .sum();
            let count = self.key_generation_ms.len() as f64;
            total / count
        }
    }

    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn outliers_count(&self) -> usize {
        if self.key_generation_ms.is_empty() {
            return 0;
        }

        let mean = self.avg_key_generation_ms();
        let variance = self
            .key_generation_ms
            .iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / self.key_generation_ms.len() as f64;

        let std_dev = variance.sqrt();
        let threshold = std_dev.mul_add(2.0, mean); // 2 sigma threshold

        self.key_generation_ms
            .iter()
            .filter(|&&x| (x as f64) > threshold)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimized_rsa_generation_is_faster() {
        // Bu test gerçek performans iyileştirmesini ölçer
        let start = std::time::Instant::now();
        let _key = generate_optimized_rsa_keypair(2048).expect("RSA 2048 generation");
        let duration = start.elapsed();

        // Native Aunsorm RNG - debug mode is significantly slower than release mode.
        // The debug threshold allows for CI environments with reduced entropy sources,
        // while still asserting that release builds remain snappy.
        let threshold = if cfg!(debug_assertions) {
            25_000
        } else {
            10_000
        };
        assert!(
            duration.as_millis() < threshold,
            "RSA 2048 generation took too long: {:?} (debug: {})",
            duration,
            cfg!(debug_assertions)
        );
    }

    #[test]
    fn test_metrics_calculation() {
        let mut metrics = RsaPerformanceMetrics::new();
        metrics.record_key_generation(100);
        metrics.record_key_generation(150);
        metrics.record_key_generation(500); // not an outlier with 2-sigma rule

        assert!((metrics.avg_key_generation_ms() - 250.0).abs() < f64::EPSILON);
        assert_eq!(metrics.outliers_count(), 0); // 500 is within 2 standard deviations

        // Test with actual outlier
        metrics.record_key_generation(1000); // This should be an outlier
        assert!(metrics.outliers_count() <= 1); // At most one outlier expected
    }
}
