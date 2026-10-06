# Native RNG Entropy Analysis Report

> Historical measurements of the pre-hardening implementation. Superseded by
> [ADR 0008](../../docs/architecture/adr/0008-native-rng-state-hardening.md).
> Correction (2026-10-07): for χ²=126.07 with 100 degrees of freedom,
> the upper-tail p-value is approximately 0.04005, not 0.32. Statistical
> testing does not establish cryptographic security or NIST certification.

**Analysis Date:** 2025-11-07  
**Prepared By:** Interop Agent Team

## 1. Objective
Validate statistical quality of ChaCha20-based `AunsormNativeRng` implementation.

## 2. Methodology
1. **Implementation:** ChaCha20 stream cipher with 256-bit key, 64-bit counter, 64-bit nonce (crates/core/src/sealed/aunsorm_rng.rs)
2. **Statistical Validation:** Chi-square goodness-of-fit test on 100,000 samples in [0, 100] interval
3. **Performance Analysis:** Throughput and latency measurements for 32-byte to 16KiB blocks

## 3. Statistical Results
| Interval | Samples | Mean (Observed) | Mean (Expected) | χ² Statistic | p-value |
|----------|---------|-----------------|-----------------|--------------|---------|
| [0, 100] | 100,000 | 49.996 | 50.0 | 126.07 | 0.04005 (corrected) |

The corrected single test rejects at α=0.05, but not at α=0.01. A single rejection is insufficient to diagnose generator quality. Test execution: 3.33ms for 100,000 samples.

## 4. Performance Metrics
| Block Size | Throughput | next_u64() Latency |
|------------|------------|-------------------|
| 32 bytes | 260.49 MiB/s | 32.2 ns |
| 1 KiB | 263.57 MiB/s | - |
| 16 KiB | 264.15 MiB/s | - |

RSA-2048 key generation: 137.22 ms average (10 samples).

## 5. Conclusion
The original security conclusion is withdrawn: the corrected p-value is approximately 0.04005, and statistical uniformity alone cannot certify cryptographic security. Implementation located at crates/core/src/sealed/aunsorm_rng.rs.

