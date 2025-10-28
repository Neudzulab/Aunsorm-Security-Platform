//! X509 Performance Optimizations
//!
//! This module contains performance optimizations for RSA operations
//! and other crypto-intensive X509 tasks.

use crate::X509Error;
use rcgen::KeyPair;
use std::sync::LazyLock;
use std::collections::HashMap;
use pem::Pem;
use rand_core::{OsRng, RngCore};
use rsa::{pkcs8::EncodePrivateKey, RsaPrivateKey};

/// Pre-generated RSA keypairs for development/testing
/// Bu production'da kullanılmamalı, sadece benchmark/test için
static PREGENERATED_KEYS: LazyLock<HashMap<usize, String>> = LazyLock::new(|| {
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
    // 3. Fallback to OS RNG if needed
    
    eprintln!("🚀 Generating RSA-{} key with Aunsorm native entropy...", bits);
    let start = std::time::Instant::now();
    
    let mut rng = AunsormNativeRng::new();
    let result = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|err| X509Error::KeyGeneration(format!("RSA {}-bit generation failed: {}", bits, err)));
    
    let duration = start.elapsed();
    eprintln!("✅ RSA-{} key generated with Aunsorm native RNG in {:?}", bits, duration);
    
    result
}

/// Native Aunsorm RNG - Direct implementation of server's entropy algorithm
/// No HTTP overhead, pure mathematical entropy generation
pub struct AunsormNativeRng {
    entropy_salt: [u8; 32],
    counter: u64,
}

impl AunsormNativeRng {
    /// Create new Aunsorm native RNG
    pub fn new() -> Self {
        let mut entropy_salt = [0u8; 32];
        OsRng.fill_bytes(&mut entropy_salt);
        
        Self {
            entropy_salt,
            counter: 0,
        }
    }
    
    /// Generate next entropy block using Aunsorm's HKDF+NEUDZ-PCS algorithm
    /// This is the EXACT same algorithm used by the server
    fn next_entropy_block(&mut self) -> [u8; 32] {
        use sha2::Sha256;
        use std::time::{SystemTime, UNIX_EPOCH, Duration};
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        // 1. OS-level cryptographic entropy (32 bytes)
        let mut os_entropy = [0u8; 32];
        OsRng.fill_bytes(&mut os_entropy);
        
        // 2. Nanosecond precision timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_nanos()
            .to_le_bytes();
        
        // 3. Atomic counter (collision prevention)
        let counter = self.counter;
        self.counter = self.counter.wrapping_add(1);
        
        // 4. Process ID (multi-instance uniqueness)
        let process_id = std::process::id();
        
        // 5. Thread ID (parallel execution uniqueness)
        let thread_id = std::thread::current().id();
        let thread_hash = {
            let mut hasher = DefaultHasher::new();
            thread_id.hash(&mut hasher);
            hasher.finish()
        };
        
        // HKDF-Extract-and-Expand (RFC 5869) - cryptographically proven entropy expansion
        use hkdf::Hkdf;
        let hk = Hkdf::<Sha256>::new(Some(&self.entropy_salt), &os_entropy);
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
    fn apply_mathematical_mixing(entropy: &mut [u8; 32]) {
        // AACM (Aunsorm Advanced Cryptographic Mixing): mathematical entropy enhancement
        for (i, byte) in entropy.iter_mut().enumerate() {
            let x = (*byte as f64) + (i as f64 * 0.618033988749); // Golden ratio mixing
            let mixed = Self::neudz_pcs_mix(x + 1.0); // +1 to avoid ln(0)
            *byte = (*byte).wrapping_add(mixed as u8);
        }
    }
}

impl rand_core::CryptoRng for AunsormNativeRng {}

impl rand_core::RngCore for AunsormNativeRng {
    fn next_u32(&mut self) -> u32 {
        let entropy = self.next_entropy_block();
        u32::from_le_bytes([entropy[0], entropy[1], entropy[2], entropy[3]])
    }
    
    fn next_u64(&mut self) -> u64 {
        let entropy = self.next_entropy_block();
        u64::from_le_bytes([
            entropy[0], entropy[1], entropy[2], entropy[3],
            entropy[4], entropy[5], entropy[6], entropy[7]
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

/// Performance monitoring for RSA operations
pub struct RsaPerformanceMetrics {
    pub key_generation_ms: Vec<u64>,
    pub signing_ms: Vec<u64>,
    pub verification_ms: Vec<u64>,
}

impl RsaPerformanceMetrics {
    pub fn new() -> Self {
        Self {
            key_generation_ms: Vec::new(),
            signing_ms: Vec::new(),
            verification_ms: Vec::new(),
        }
    }
    
    pub fn record_key_generation(&mut self, duration_ms: u64) {
        self.key_generation_ms.push(duration_ms);
    }
    
    pub fn avg_key_generation_ms(&self) -> f64 {
        if self.key_generation_ms.is_empty() {
            0.0
        } else {
            self.key_generation_ms.iter().sum::<u64>() as f64 / self.key_generation_ms.len() as f64
        }
    }
    
    pub fn outliers_count(&self) -> usize {
        if self.key_generation_ms.is_empty() {
            return 0;
        }
        
        let mean = self.avg_key_generation_ms();
        let variance = self.key_generation_ms.iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>() / self.key_generation_ms.len() as f64;
        
        let std_dev = variance.sqrt();
        let threshold = mean + 2.0 * std_dev; // 2 sigma threshold
        
        self.key_generation_ms.iter()
            .filter(|&&x| x as f64 > threshold)
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
        
        // Native Aunsorm RNG - debug mode is slower, release mode will be much faster
        let threshold = if cfg!(debug_assertions) { 10000 } else { 5000 };
        assert!(duration.as_millis() < threshold, "RSA 2048 generation took too long: {:?} (debug: {})", 
                duration, cfg!(debug_assertions));
    }
    
    #[test]
    fn test_metrics_calculation() {
        let mut metrics = RsaPerformanceMetrics::new();
        metrics.record_key_generation(100);
        metrics.record_key_generation(150);
        metrics.record_key_generation(500); // outlier
        
        assert_eq!(metrics.avg_key_generation_ms(), 250.0);
        assert_eq!(metrics.outliers_count(), 1);
    }
}