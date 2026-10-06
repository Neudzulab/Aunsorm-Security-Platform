# ADR 0008: Harden native RNG state lifecycle

- **Status:** Proposed (maintainer review pending)
- **Date:** 2026-10-07
- **Supersedes:** ADR 0001's initial-seeding-only restriction
- **Plan task:** PROD_PLAN.md → Native RNG Compliance → Revize: Harden native RNG state lifecycle

## Context

The prior RNG's derived Debug exposed its complete secret state. A state
snapshot reproduced 8000 future bytes before the next timestamp update, and
its current key recovered 2016 past bytes within the same key epoch. Copied
process state repeated output; rekeying incorporated no fresh OS entropy.
The mathematical transforms had no established additional security benefit.
Statistical test/benchmark helpers also returned incorrect p-values.

## Decision

Keep the public `AunsormNativeRng` facade and RustCrypto ChaCha20 primitive.
Replace each buffer refill with the fast-key-erasure construction: generate
1056 keystream bytes, reserve the first 32 for the next key, and expose only
the remaining 1024. Erase the old key and consumed buffered output. Enable
RustCrypto's zeroize feature to wipe temporary cipher state on drop.

Use fresh 32-byte OS seeds at initialization, after 64 KiB of generated
output, on PID changes (before reading inherited buffered bytes), and on an
explicit `reseed()` call. XOR the fresh seed with the existing secret key;
an independent uniform OS seed makes the result uniform, while an exposed
later seed alone does not disclose an unknown existing key. Never treat the
clock, PID, mathematical functions, or rekeying as fresh entropy.

Add `try_new()` and `reseed()` while retaining existing infallible methods.
Entropy failure returns an error from fallible methods, clears a partially
filled destination, and blocks further output until a reseed succeeds.
Infallible methods panic rather than silently falling back. Debug is fully
redacted. Statistical helpers use the chi-square survival function through
`statrs`, shared between tests and benchmarks.

## Limits and consequences

- Same-PID VM/process snapshot restores are not detectable: the caller must
  invoke `reseed()` successfully before reading any restored output.
- A memory reader still sees unconsumed buffered output and the current key.
  Recovery depends on fresh OS entropy remaining secret.
- Tests use controlled PID mismatch to exercise the child-process path; this
  is not an actual fork integration test. The library forbids unsafe code.
- All prior deterministic stream values and speed claims are obsolete; callers
  were never promised reproducibility for this OS-seeded generator.
- This construction is based on a published RNG design, but this particular
  integration has not received independent cryptographic certification.
- Completed historical plan items remain unchanged; this revision records the
  corrected lifecycle and invalidates their use as evidence for new code.

## Alternatives

Wrapping `ChaCha20Rng` alone would improve throughput but would not by itself
erase consumed state or provide the required lifecycle. Retaining the custom
floating-point transformations complicates analysis without a proven benefit.
Using OS randomness for every call avoids persistent PRNG state but increases
OS calls; the selected design amortizes seeding over bounded output.

## References

- https://blog.cr.yp.to/20170723-random.html — fast-key-erasure RNG design
- https://csrc.nist.gov/pubs/sp/800/22/r1/upd1/final — statistical tests cannot replace cryptanalysis
- `crates/core/src/sealed/aunsorm_rng.rs`
- `tests/support/rng_statistics.rs`
- `certifications/audit/native_rng_entropy_analysis.md` — corrected historical evidence
