//! OS-seeded `ChaCha20` RNG with fast key erasure and bounded reseeding.
//!
//! Each refill reserves the first 32 keystream bytes for the next key and
//! exposes only the remaining bytes. Consumed output is erased immediately.
//! This follows the fast-key-erasure construction described at
//! <https://blog.cr.yp.to/20170723-random.html>; it is not a NIST certification.

use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use rand_core::{OsRng, RngCore};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

const BUFFER_LEN: usize = 1024;
const RESEED_BYTES: usize = 64 * 1024;

/// Aunsorm's native cryptographic random-number generator.
///
/// Seeds and reseeds from the OS, including after a process-ID change and at
/// most every 64 KiB of generated output. Every buffer refill replaces the key;
/// consumed buffer bytes and the cipher's temporary state are zeroized.
///
/// A snapshot restored with the same PID cannot be detected automatically.
/// Call [`Self::reseed`] before using a restored instance. An attacker with
/// access to live memory can still read unconsumed output and predict future
/// output until fresh, secret OS entropy is incorporated.
///
/// ```
/// use aunsorm_core::AunsormNativeRng;
/// use rand_core::RngCore;
/// let mut rng = AunsormNativeRng::try_new()?;
/// let mut nonce = [0_u8; 12];
/// rng.try_fill_bytes(&mut nonce)?;
/// # Ok::<(), rand_core::Error>(())
/// ```
pub struct AunsormNativeRng {
    key: [u8; 32],
    entropy_buffer: [u8; BUFFER_LEN],
    buffer_offset: usize,
    generated_bytes: usize,
    process_id: u32,
    reseed_required: bool,
}

impl fmt::Debug for AunsormNativeRng {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AunsormNativeRng { state: [REDACTED] }")
    }
}

impl AunsormNativeRng {
    /// Creates an OS-seeded RNG.
    ///
    /// # Panics
    /// Panics if the operating system cannot provide secure randomness.
    /// Use [`Self::try_new`] to handle this error explicitly.
    #[must_use]
    pub fn new() -> Self {
        Self::try_new().expect("Aunsorm RNG initialization failed")
    }

    /// Creates an OS-seeded RNG, propagating entropy-source failures.
    ///
    /// # Errors
    /// Returns an error if the OS randomness source fails.
    pub fn try_new() -> Result<Self, rand_core::Error> {
        let mut rng = Self {
            key: [0; 32],
            entropy_buffer: [0; BUFFER_LEN],
            buffer_offset: BUFFER_LEN,
            generated_bytes: 0,
            process_id: std::process::id(),
            reseed_required: true,
        };
        rng.reseed()?;
        Ok(rng)
    }

    /// Incorporates fresh OS randomness and discards all buffered output.
    ///
    /// Call this after restoring a snapshot, before producing any output.
    ///
    /// # Errors
    /// Returns an error if the OS randomness source fails. Further output is
    /// blocked until a reseed succeeds; retry or drop the RNG.
    pub fn reseed(&mut self) -> Result<(), rand_core::Error> {
        self.reseed_from(&mut OsRng)
    }

    fn reseed_from(&mut self, source: &mut impl RngCore) -> Result<(), rand_core::Error> {
        self.reseed_required = true;
        let mut seed = Zeroizing::new([0_u8; 32]);
        source.try_fill_bytes(seed.as_mut())?;
        // Retain the existing secret even if a later seed is weak. Fresh
        // independent OS entropy also recovers from an exposed old state.
        for (seed_byte, key_byte) in seed.iter_mut().zip(&self.key) {
            *seed_byte ^= key_byte;
        }
        self.key.zeroize();
        self.key.copy_from_slice(seed.as_ref());
        self.entropy_buffer.zeroize();
        self.buffer_offset = BUFFER_LEN;
        self.generated_bytes = 0;
        self.process_id = std::process::id();
        self.reseed_required = false;
        Ok(())
    }

    fn refill(&mut self) {
        let mut block = Zeroizing::new([0_u8; BUFFER_LEN + 32]);
        // A fresh key is installed before any output leaves this instance;
        // the fixed nonce is never reused with a deliberately retained key.
        let mut cipher = ChaCha20::new((&self.key).into(), (&[0_u8; 12]).into());
        cipher.apply_keystream(block.as_mut());
        self.key.zeroize();
        self.key.copy_from_slice(&block[..32]);
        self.entropy_buffer.copy_from_slice(&block[32..]);
        self.buffer_offset = 0;
        self.generated_bytes += BUFFER_LEN;
    }

    fn ensure_ready(&mut self, source: &mut impl RngCore) -> Result<(), rand_core::Error> {
        // Check before using even already-buffered bytes inherited by a child.
        if self.reseed_required
            || self.process_id != std::process::id()
            || (self.buffer_offset == BUFFER_LEN && self.generated_bytes >= RESEED_BYTES)
        {
            self.reseed_from(source)?;
        }
        if self.buffer_offset == BUFFER_LEN {
            self.refill();
        }
        Ok(())
    }

    fn wipe(&mut self) {
        self.key.zeroize();
        self.entropy_buffer.zeroize();
        self.buffer_offset.zeroize();
        self.generated_bytes.zeroize();
        self.process_id.zeroize();
        self.reseed_required.zeroize();
    }
}

impl RngCore for AunsormNativeRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = Zeroizing::new([0; 4]);
        self.fill_bytes(bytes.as_mut());
        u32::from_le_bytes(*bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = Zeroizing::new([0; 8]);
        self.fill_bytes(bytes.as_mut());
        u64::from_le_bytes(*bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("Aunsorm RNG entropy refresh failed");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_from(dest, &mut OsRng)
    }
}

impl AunsormNativeRng {
    fn fill_from(
        &mut self,
        dest: &mut [u8],
        source: &mut impl RngCore,
    ) -> Result<(), rand_core::Error> {
        let mut offset = 0;
        while offset < dest.len() {
            if let Err(error) = self.ensure_ready(source) {
                // Do not return a partially generated secret on failure.
                dest.zeroize();
                return Err(error);
            }
            let size = (BUFFER_LEN - self.buffer_offset).min(dest.len() - offset);
            let consumed = &mut self.entropy_buffer[self.buffer_offset..self.buffer_offset + size];
            dest[offset..offset + size].copy_from_slice(consumed);
            consumed.zeroize();
            self.buffer_offset += size;
            offset += size;
        }
        Ok(())
    }
}

impl Default for AunsormNativeRng {
    fn default() -> Self {
        Self::new()
    }
}

impl rand_core::CryptoRng for AunsormNativeRng {}

impl Drop for AunsormNativeRng {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_rng() -> AunsormNativeRng {
        AunsormNativeRng {
            key: [42; 32],
            entropy_buffer: [0; BUFFER_LEN],
            buffer_offset: BUFFER_LEN,
            generated_bytes: 0,
            process_id: std::process::id(),
            reseed_required: false,
        }
    }

    #[test]
    fn debug_redacts_all_state() {
        let mut rng = fixed_rng();
        rng.next_u64();
        assert_eq!(format!("{rng:?}"), "AunsormNativeRng { state: [REDACTED] }");
        assert_eq!(format!("{rng:#?}"), format!("{rng:?}"));
    }

    #[test]
    fn erases_old_key_and_consumed_output() {
        let mut rng = fixed_rng();
        let mut cipher = ChaCha20::new((&rng.key).into(), (&[0_u8; 12]).into());
        let mut stream = [0; BUFFER_LEN + 32];
        cipher.apply_keystream(&mut stream);
        let mut output = [0; 37];
        rng.fill_bytes(&mut output);
        assert_eq!(output, stream[32..69]);
        assert_eq!(rng.key, stream[..32]);
        assert_ne!(rng.key, [42; 32]);
        assert!(rng.entropy_buffer[..37].iter().all(|&byte| byte == 0));
        assert_eq!(rng.entropy_buffer[37..], stream[69..]);
        let key = rng.key;
        rng.fill_bytes(&mut [0; BUFFER_LEN - 37]);
        assert!(rng.entropy_buffer.iter().all(|&byte| byte == 0));
        rng.next_u64();
        assert_ne!(rng.key, key);
    }

    #[test]
    fn mixed_calls_preserve_stream_across_refills() {
        let mut whole = fixed_rng();
        let mut split = fixed_rng();
        let mut expected = vec![0; 3 * BUFFER_LEN + 9];
        whole.fill_bytes(&mut expected);
        let mut actual = Vec::new();
        actual.extend(split.next_u32().to_le_bytes());
        split.fill_bytes(&mut [0; 0]);
        let mut bytes = vec![0; BUFFER_LEN - 5];
        split.fill_bytes(&mut bytes);
        actual.extend(bytes);
        actual.extend(split.next_u64().to_le_bytes());
        let mut tail = vec![0; expected.len() - actual.len()];
        split.fill_bytes(&mut tail);
        actual.extend(tail);
        assert_eq!(actual, expected);
    }

    #[test]
    fn pid_change_discards_inherited_buffer() {
        let mut child = fixed_rng();
        child.fill_bytes(&mut [0; 1]);
        let inherited = child.entropy_buffer[1..33].to_vec();
        child.process_id = child.process_id.wrapping_add(1);
        let mut output = [0; 32];
        child.fill_bytes(&mut output);
        assert_ne!(output.as_slice(), inherited.as_slice());
        assert_eq!(child.process_id, std::process::id());
        assert_eq!(child.buffer_offset, 32);
        assert_eq!(child.generated_bytes, BUFFER_LEN);
    }

    #[test]
    fn reseeds_at_output_limit_including_large_calls() {
        let mut rng = fixed_rng();
        rng.fill_bytes(&mut vec![0; RESEED_BYTES]);
        assert_eq!(rng.generated_bytes, RESEED_BYTES);
        rng.fill_bytes(&mut vec![0; RESEED_BYTES + 1]);
        assert_eq!(rng.generated_bytes, BUFFER_LEN);
        assert_eq!(rng.buffer_offset, 1);
    }

    #[test]
    fn explicit_reseed_discards_same_pid_snapshot_buffer() {
        let mut restored = fixed_rng();
        restored.fill_bytes(&mut [0; 7]);
        let key = restored.key;
        restored.reseed().unwrap();
        assert_ne!(restored.key, key);
        assert!(restored.entropy_buffer.iter().all(|&byte| byte == 0));
        assert_eq!(restored.buffer_offset, BUFFER_LEN);
        assert_eq!(restored.generated_bytes, 0);
    }

    struct FailingEntropy;
    impl RngCore for FailingEntropy {
        fn next_u32(&mut self) -> u32 {
            panic!("infallible entropy API must not be used")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("infallible entropy API must not be used")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("infallible entropy API must not be used")
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            dest.fill(7);
            Err(rand_core::Error::new(std::io::Error::other(
                "entropy unavailable",
            )))
        }
    }

    #[test]
    fn failed_reseed_blocks_output_until_recovery() {
        let mut rng = fixed_rng();
        rng.next_u64();
        let key = rng.key;
        let buffer = rng.entropy_buffer;
        let offset = rng.buffer_offset;
        assert!(rng.reseed_from(&mut FailingEntropy).is_err());
        assert_eq!(rng.key, key);
        assert_eq!(rng.entropy_buffer, buffer);
        assert_eq!(rng.buffer_offset, offset);
        assert!(rng.reseed_required);
        let mut output = [99; 16];
        assert!(rng.fill_from(&mut output, &mut FailingEntropy).is_err());
        assert_eq!(output, [0; 16]);
        rng.reseed().unwrap();
        assert!(!rng.reseed_required);
        assert!(rng.try_fill_bytes(&mut output).is_ok());
    }

    #[test]
    fn refresh_failure_erases_partially_filled_destination() {
        let mut rng = fixed_rng();
        rng.refill();
        rng.buffer_offset = BUFFER_LEN - 1;
        rng.generated_bytes = RESEED_BYTES;
        let mut output = [99; 2];
        assert!(rng.fill_from(&mut output, &mut FailingEntropy).is_err());
        assert_eq!(output, [0; 2]);
        assert!(rng.reseed_required);
    }

    #[test]
    fn zeroizes_sensitive_state_on_drop() {
        let mut rng = AunsormNativeRng::new();
        rng.fill_bytes(&mut [0; 64]);
        rng.wipe();
        assert!(rng.key.iter().all(|&byte| byte == 0));
        assert!(rng.entropy_buffer.iter().all(|&byte| byte == 0));
        assert_eq!(rng.buffer_offset, 0);
        assert_eq!(rng.generated_bytes, 0);
        assert_eq!(rng.process_id, 0);
    }
}
