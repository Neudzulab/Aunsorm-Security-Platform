# Native RNG Performance Benchmarks

**Benchmark Date:** 2025-11-07  
**Implementation:** ChaCha20-based AunsormNativeRng (crates/core/src/sealed/aunsorm_rng.rs)

## 1. Throughput Benchmarks
| Block Size | Throughput (MiB/s) |
|------------|-------------------|
| 32 bytes | 260.49 |
| 1 KiB | 263.57 |
| 16 KiB | 264.15 |

## 2. Latency Benchmarks
| Operation | Mean Latency |
|-----------|--------------|
| next_u64() | 32.2 ns |

## 3. Statistical Quality Test
| Test | Sample Size | Execution Time |
|------|-------------|----------------|
| Chi-square [0,100] | 100,000 | 3.33 ms |

Chi-square statistic: 126.07, p-value: 0.32

## 4. Cryptographic Operations
| Operation | Mean Time | Samples |
|-----------|-----------|---------|
| RSA-2048 Key Generation | 137.22 ms | 10 |

## 5. Reproduction
```bash
cargo bench --bench rng_comparison
```

Benchmarks run on sealed ChaCha20 implementation located at crates/core/src/sealed/aunsorm_rng.rs.

