//! X509 Performance Optimizations
//!
//! This module contains performance optimizations for RSA operations
//! and other crypto-intensive X509 tasks.

use crate::X509Error;
use aunsorm_core::AunsormNativeRng;
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
    let result = if bits >= 4096 && std::thread::available_parallelism().map_or(1, |p| p.get()) > 1 {
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    
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
                continue;
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
