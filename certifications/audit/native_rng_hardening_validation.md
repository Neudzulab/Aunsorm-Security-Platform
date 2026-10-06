# Native RNG hardening validation — 2026-10-07

Base commit: `c7903f04118e0184921ada41c7634e39427b7a35`.
Design: [ADR 0008](../../docs/architecture/adr/0008-native-rng-state-hardening.md).
Task: `PROD_PLAN.md` → Native RNG Compliance → Revize: Harden native RNG state lifecycle.

## Checked behavior

Regression tests cover redacted Debug output, separate next-key/output bytes,
erasure of consumed output, consistent mixed RngCore calls across refills,
PID-change reseeding before inherited output is used, the 64 KiB reseed bound,
same-PID explicit reseeding, partial entropy-source failure, recovery after
failed reseeding, clearing a partially filled destination on failure, and
state zeroization. Actual OS reseeding is exercised; error-only tests inject
a failing entropy provider. PID mismatch is simulated, not an actual fork.

## Results

Rust 1.99.0 on x86_64 Linux; MSRV 1.76 was not verified.

- `cargo test --all-features --locked`: 570 passed, 18 pre-existing ignored,
  zero failures and zero compiler warnings across 58 test/doc-test suites.
- `cargo test -p aunsorm-core --all-features --locked`: 66 unit tests and
  20 doc tests passed.
- `cargo test -p aunsorm-tests --test rng_statistical_validation --locked -- --include-ignored --nocapture`: all 7 tests passed, including the three long-running tests.
- The final statistical integration-test source was also run in a release
  harness linked directly to the real `aunsorm-core` crate: 7 tests passed,
  including 10M + 10M + 5M samples and exact-p-value regression cases.
- `cargo check -p interop-benches --bench rng_comparison --locked`: passed
  without warnings after moving shared-helper tests into the integration suite.
- `cargo clippy -p aunsorm-core --lib --all-features --locked`: passed.
- `cargo fmt --all -- --check` and `git diff --check`: passed.

A separate 128 MiB output sample was checked with NumPy 2.3.5/SciPy 1.17.0.
Across 92 aggregate/frequency/bit/runs/pair/correlation checks, including
four modulo-4 block phases and 32 byte positions, no result crossed the
Bonferroni threshold 0.01/92. The 1024 contiguous 1-Mibit sequences had
1010 monobit and 1015 runs passes at alpha=0.01; their p-value uniformity
p-values were 0.77829 and 0.20063. A few individual rejections at that
threshold are expected. This is not the full NIST STS or PractRand suite.

Sample SHA256:
`ab70f82f515c5a552e8462c68b489f8f8c41ba9b07b64b2c4fe83ade4c442f71`.
The sample used a fresh OS seed; its exact values are not reproducible.

For five release runs generating 128 MiB into 16 KiB buffers (no file I/O),
median throughput was 869.59 MiB/s native and 1897.62 MiB/s ChaCha20Rng.
An earlier measurement of the old implementation was 169.42 MiB/s; system
load differed, so this is indicative improvement, not a controlled universal
speedup. Native lifecycle checks/zeroization/reseeding have additional cost
compared with the unwrapped reference. The committed Criterion benchmark now
includes both implementations for same-run comparisons.

## Inherited quality-gate blockers

Do not interpret these test results as a clean platform-wide security audit.

- Full `cargo clippy --all-targets --all-features --locked` fails at an existing
  derivable Default implementation in `crates/x509/src/ca.rs`. The same command
  against the unmodified base commit reproduces that error. Core all-targets
  Clippy also flags the unchanged `assert!(event.public_key.is_empty())` in
  `crates/core/src/transparency.rs` under Clippy 1.99.
- `cargo deny check` (cargo-deny 0.20.2) fails with 15 advisory IDs and a yanked
  `spin` warning. The base commit was checked separately and reports the exact
  same IDs. New `statrs`/`approx` dependencies introduce no additional advisory
  IDs; bans, licenses and sources pass. Existing alerts cover anyhow,
  crossbeam-epoch, h2, PQClean crates, quick-xml, rand, rustls and rustls-webpki.
  The four PQClean alerts concern maintenance status; the remaining alerts
  include soundness/vulnerability findings. None were ignored or suppressed.
- Resolving these inherited dependency and Clippy issues needs separate scoped
  work; the RNG revision task stays unchecked pending review and quality gates.

## Remaining limits

Debug/log disclosure is closed at this type, but arbitrary live-memory reads
still reveal unconsumed output and the current key. Fresh secret OS entropy
is required for recovery. Same-PID snapshots must explicitly reseed before
use; no automatic snapshot detection is claimed. No independent security
certification, NIST SP 800-90 compliance certification, actual fork integration
test, or full platform production-readiness claim is made.

References: [fast key erasure](https://blog.cr.yp.to/20170723-random.html),
[NIST statistical-test limitations](https://csrc.nist.gov/pubs/sp/800/22/r1/upd1/final).
