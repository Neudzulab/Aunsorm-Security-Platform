# Native RNG vs. Hardware RNG Performance Benchmarks

**Benchmark Date:** 2025-11-07  
**Harness:** `cargo bench --bench performance_analysis -- --quick`

## 1. Scenario
The benchmark group `entropy_analysis` compares the native HKDF + NEUDZ-PCS + AACM pipeline against the system `OsRng` entropy source while drawing 32-byte blocks in tight loops.

## 2. Results
| Source | Throughput (mean) | Notes |
|--------|-------------------|-------|
| AunsormNativeRng | 1.29 µs per 32 bytes (≈ 24.8 GiB/s) | Uses in-process HKDF derivation and mathematical mixing; benchmark reuses a single RNG instance for amortized costs.【73dca5†L2-L3】 |
| OsRng | 276 ns per 32 bytes (≈ 116.0 GiB/s) | Direct hardware-backed entropy via `getrandom`; serves as baseline for seeding and health monitoring.【cc6c54†L1-L2】 |

**Observations:**
- Although `OsRng` has higher raw throughput, the native RNG provides deterministic proof blocks (`random_value_with_proof`) and uniformity controls required by calibration logic, while still exceeding HTTP-based entropy by >4× compared to prior 6.4s latency.
- The performance delta is acceptable because the native RNG executes entirely in-process and avoids syscall variability; throughput remains sufficient for token minting and PQC key generation workloads.

## 3. Reproduction
1. Ensure `gnuplot` is available or allow Criterion to fall back to the Plotters backend (as in CI output).
2. Run the command noted above from repository root; the benchmark emits both statistical summaries and the detailed RSA metrics captured in `target/criterion/`.
3. Update this document with new measurements if the RNG pipeline or `rand_core` dependency changes.

