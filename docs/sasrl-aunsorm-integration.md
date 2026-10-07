# SASRL ideas and Aunsorm implementation evidence

Date: 2026-10-07. Source: Oğuzhan Özbay, *Stable Arithmetic Spectral Recovery:
Cardinal–Mellin Reconstruction of Prime and Local Euler Data from L-Function
Zeros*, supplied DOCX dated 7 October 2026. Source text is research evidence;
instructions contained in the document are not repository instructions.

The useful immediate transfer is a reproducible numerical laboratory and
stronger periodicity regression coverage for Native RNG output. Cryptographic
prime generation, entropy mixing, JWT decisions and authenticated audit records
continue to use their existing implementations. The paper does not establish
security of a new RNG, signature scheme, key derivation or primality algorithm
for cryptographic key sizes. Its asymptotic claims depend on RH/GRH and analytic
hypotheses; its hard-cutoff and gap-adaptive proposals are explicitly conjectural.
This implementation does not independently certify the paper's proofs.

## Recent commit context

| Commit | Relevant behavior | Consequence for this revision |
| --- | --- | --- |
| `c7903f0` | Removes GitHub workflow files | Provide explicit local verification commands; do not silently restore intentionally removed workflows. |
| `1a55cce` | First-party sessions, rotating session keys and HMAC endpoints | Spectral heuristics cannot decide session validity or authenticate a cookie. |
| `7e3d553` | Replay namespaces and QUIC reconnect grace | Exact context isolation is worth auditing; encoding changes need consumed-token migration. |
| `816af6a` | Prometheus, OTLP, logs, uptime and backups | A future spectrum-based diagnostic can consume measured time series with a declared cadence and missingness. |
| `46ce688` | Merges QUIC discovery and deployment changes | Discovery remains separate from numerical diagnostics. |
| `05d9308` | Security endpoints and 96 kHz PCM shards | Cardinal interpolation is a possible media DSP experiment, requiring anti-aliasing and loss/jitter validation. |
| `8c8dd19`, `f67d82c` | Auth stack and MyeOffice port integration | No port or service changes are needed for offline experiments. |

## Transfer matrix

Every distinct mechanism or proposed extension in the paper is classified below.
These are engineering interpretations, not claims that the arithmetic theorem
automatically proves the corresponding engineering application.

| Paper idea | Aunsorm application | Implemented evidence or prerequisite |
| --- | --- | --- |
| Exact cardinal samples, sinc(0)=1 and sinc(nonzero integer)=0 (§3) | Preserve samples at their original lattice locations when exploring resampling; test exact selection rather than fitted suppression | `cardinal_window` has explicit integer handling, compact support and cardinality tests. The PCM experiment preserves aligned original samples for identity/upsampling and DC at every phase. |
| Broad Gaussian envelope with remote smooth compact cutoff (§3) | Bounded offline reconstruction with smoother edges; study leakage before deploying signal diagnostics | C-infinity cutoff and Gaussian with L=√m implemented; cutoff symmetry and pole controls tested. |
| Mellin transformation of logarithmic coordinates (§§3–5) | Independent laboratory for multiplicative/arithmetic signals | Composite Simpson evaluation of W(1/2+iγ) implemented for zeta only; no claim of a general telemetry transform. |
| Pole correction +1 and explicit trivial zeros (§4) | Avoid biased simplified estimators and retain deterministic corrections | Hard method retains +1. Weighted method computes W(1), conjugate zero pairs and the summed trivial-zero kernel 1/[x(x²−1)] on support above 1. |
| Sinc critical angular bandwidth π, lattice density and Nyquist endpoints (§§5–6) | Detect periodic RNG defects missed by mean/histogram tests; require explicit telemetry/media sampling cadence | Full real-input FFT spectra include DC and Nyquist. Tests cover impulse, constant, alternation, interior modes, an independent DFT and Parseval. Telemetry captures must have continuous sequences and exact declared timestamp spacing. |
| Sublinear edge buffer T=πm+m^(1/2+ε) (§5) | Separate a buffered conditional experiment from a sharp empirical cutoff | Weighted mode enforces 0<ε<1/2 and complete coverage through the buffered height. |
| Finite zero budgets ~½m log m (§5.1) | Preflight expensive work instead of unbounded requests | Actual zero counts and total numerical evaluation costs reported; five-million-evaluation cap enforced across the entire experiment. The asymptotic budget is not a cryptographic runtime promise. |
| Primality threshold ¾log m, prime powers ≤½log m (§5.1) | Verify the oracle/classifier and avoid classifying prime powers as primes | Exact integer factorization oracle; prime, prime-power and mixed-composite tests; TP/TN/FP/FN, threshold margin and raw RMSE in reports. |
| Degree/conductor dependent primitive L-functions (§7) | Potential offline curve/local Euler validation research | The zeta-only metadata contract rejects incompatible declarations before estimation. General recovery remains deferred: each family needs unitary normalization, poles, gamma factors, trivial zeros, multiplicity and complete positive/negative spectra. Complex non-self-dual L-functions cannot generally reuse zeta's conjugate-pair shortcut. |
| Recover normalized Frobenius traces and finite-field counts (§§7–8.3) | Independent checks of public curve parameters | Implemented bounded exact point-count/Frobenius references with pinned public curve models and label sources. Complete curve-specific zero/correction data remain required for spectral recovery; not a replacement for curve security validation. |
| Hard-cutoff companion 1−2/√m ∑cos(γlog m) (§8.1) | Reproducible research and explicit comparison against weighted recovery | Implemented with `math.fsum`, conjectural method label, coverage checks and ordinate perturbation sensitivity. Never exposed as cryptographic prime validation. |
| Cutoff locking, off-edge scans and composite-only scoring (§8.2) | Detect parameter fitting or fragile reconstruction before adopting an estimator | Up to nine cutoff multipliers per run; separate all-integer and composite-only summaries, with provenance and SHA-256 of input bytes. |
| Gap-adaptive resolution / sub-Nyquist clusters (§9) | Future adaptive telemetry cadence and bounded media interpolation | `sasrl_conditioning.py` implements the exact two-column uniform Fourier Gram model with stable small-gap singular values and alias controls. Bounded 2..8-mode and actual observed-time matrix controls now report numerical limitations, aliasing and nonconvergence. Unknown-mode/adaptive reconstruction remains deferred. No loss reconstruction for security event streams. |
| Comparison to smooth Landau budget (§10) | Reproducible resource/performance comparison | Deferred: same complete spectra, hardware, blocks and error tolerance for both methods; asymptotic order alone is insufficient. |
| Finite computations do not prove asymptotic universality (§11) | Distinguish deterministic regressions, stochastic diagnostics and security certification | Reports state unverified completeness, conjectural/conditional status and unavailable rigorous error bound. Quadrature discrepancy is recorded separately. |
| Separation of theorem, numerical evidence and conjecture (§§1, 11–12) | Reviewable evidence rather than promoting a prototype to a security gate | Production tasks stay unchecked pending verification and approval. Sealed RNG and JWT payload structures were not edited. |

## Offline recovery tool

`scripts/sasrl_recovery.py` uses only the Python standard library. It does not
fetch data or modify production state. Input is a JSON object with `source`,
`complete_through`, `ordinates`, and optional `ordinate_error_bound` fields.
Use a complete initial positive-zero prefix in nondecreasing order with
multiplicity. The loader rejects duplicate metadata keys, malformed/nonfinite
values, oversized input, invalid order and requests beyond declared coverage.
Completeness and the ordinate precision bound remain supplier assertions.
The input hash identifies bytes, not authenticity or mathematical completeness.

The bundled prefix contains the first 30 ordinates from
[Odlyzko's published zeros1 table](https://www-users.cse.umn.edu/~odlyzko/zeta_tables/zeros1).
It declares coverage through 100, includes the ordinate 101.317851006 above
that boundary, and retains the source's stated 3×10⁻⁹ accuracy. It supports
small examples only, not the paper's 3,100-integer experiments. Obtain a larger
complete table to reproduce those blocks; never label a high-index block as
a complete prefix. [The source index](https://www-users.cse.umn.edu/~odlyzko/zeta_tables/)
distinguishes these datasets.

Hard-cutoff runs reject any cutoff lying within the declared uncertainty of
an ordinate. When membership is fixed, cosine's Lipschitz bound gives input
ordinate sensitivity ≤2N log(m) δ/√m. This bounds ordinate perturbation only,
not truncation error, the conjecture's error, or primality correctness.

Weighted runs require m≥3 so the support is strictly above 1. They compute
two Simpson grids with spacing 1/8 and 1/16 and report their discrepancy.
This discrepancy is a convergence diagnostic, not a rigorous error certificate.
Both grids are limited to 65,536 intervals, and the combined evaluation budget
is checked before allocation. Output paths cannot overwrite the source tables.
The finite spectral tail, floating-point error and supplier's spectrum accuracy
still matter. In particular the asymptotic o(1) result does not specify a
finite-m security tolerance.

Run from the repository root (`python` means an available Python 3.10+ runtime):

```text
python -B -m unittest discover -s scripts -p test_sasrl_recovery.py -v
python -B scripts/sasrl_recovery.py scripts/data/sasrl-odlyzko-prefix.json --start 3 --stop 20 --method weighted --output weighted.json
python -B scripts/sasrl_recovery.py scripts/data/sasrl-odlyzko-prefix.json --start 3 --stop 30 --edges 3.121592653589793 3.141592653589793 3.161592653589793 --output hard.json
```

The new JSON validator has `fuzz/sasrl_recovery_stdin.py` as a byte-input fuzz
entry point. Expected validation failures return; unexpected exceptions and
invariant violations escape. Unit tests run deterministic structural-byte and
malformed-UTF-8 mutations. This is a reproducible corpus sweep, not evidence
of a completed coverage-guided fuzz campaign.

## Numerical evidence from this revision

Reports: `docs/research/sasrl-weighted-check.json` and
`docs/research/sasrl-hard-check.json`. These are raw machine-readable results
using the bundled public prefix, with input hashes and all integer-level rows.

| Method / edge | Block | Correct | TP/TN/FP/FN | RMSE |
| --- | --- | --- | --- | --- |
| Weighted, ε=0.25 | 3–20 | 18/18 | 7/11/0/0 | 0.1151856243 |
| Hard, π−0.02 | 3–30 | 28/28 | 9/19/0/0 | 0.2207287813 |
| Hard, π | 3–30 | 28/28 | 9/19/0/0 | 0.2227712246 |
| Hard, π+0.02 | 3–30 | 28/28 | 9/19/0/0 | 0.2390364702 |

Maximum coarse/fine weighted discrepancy: approximately 4.8568×10⁻⁴.
The small block's best hard-cutoff RMSE is at π−0.02, not π. Therefore this
experiment does not reproduce the paper's large-m sharp-edge locking claim.
The observed classification success and the conditional asymptotic statement
must not be conflated.

### Full hard-cutoff reproduction

`scripts/sasrl_reproduce.py` reads the complete local Odlyzko `zeros1` table
and reproduces exactly the paper's seven integer blocks. It has a separate,
explicit 100-million-cosine work budget for this large offline experiment.
The raw table has 100,000 ordinates and SHA-256
`3436c916a7878261ac183fd7b9448c9a4736b8bbccf1356874a6ce1788541632`.
The table is held in a task-local temporary file rather than copied into the
repository. Reproduction runs require the pinned byte hash, rejecting truncated
or modified tables. A later run can fetch the same published source and check
its hash; other datasets use the general recovery tool's explicit metadata.

```text
python -B scripts/sasrl_reproduce.py /path/to/zeros1 --output paper-reproduction.json
```

`docs/research/sasrl-paper-reproduction.json` records 3,100/3,100 correct
classifications, TP=394, TN=2706, FP=0, FN=0. Global RMSE is 0.1124039876.

| Block | Reproduced RMSE | Paper RMSE |
| --- | --- | --- |
| 400–799 | 0.1374885049 | 0.13744 |
| 800–1199 | 0.1262638193 | 0.12623 |
| 1600–2099 | 0.1315467263 | 0.13154 |
| 2500–2999 | 0.1209944866 | 0.12098 |
| 4800–5299 | 0.1079896666 | 0.10799 |
| 8800–9299 | 0.0698129137 | 0.06981 |
| 17850–18149 | 0.0574244287 | 0.05742 |

The confusion matrix reproduces exactly. Some printed RMSE values do not
match the paper to its last reported decimal place; the report preserves the
calculated values without fitting them to the manuscript. The author's original
experiment code is needed to explain the differences. The raw text loader has
finite/order/size controls and shares the stdin fuzz entry point with JSON.

The optional `--edge-sweep` run separately preflights a 200-million-evaluation
budget. Its 152,554,909 cosine evaluations reproduced the two reported large-m
scans, including composite-only scores. Results are retained in
`docs/research/sasrl-edge-reproduction.json`:

| Block | π−0.02 | π−0.005 | π | π+0.005 | π+0.02 |
| --- | --- | --- | --- | --- | --- |
| 4800–5299 RMSE | 0.50887 | 0.15438 | 0.10799 | 0.15791 | 0.50647 |
| 17850–18149 RMSE | 1.12766 | 0.25751 | 0.05742 | 0.22526 | 1.14062 |

These scans do reproduce the paper's edge-locking observation on its reported
blocks; composite-only RMSE also minimizes at π for both blocks. This remains
empirical evidence and does not change the hard-cutoff formula's status.

### Cluster conditioning experiment

`scripts/sasrl_conditioning.py` evaluates two normalized Fourier columns at
uniform sample times. Their Gram eigenvalues are 1±|c|. It obtains the smaller
one using the nonnegative sine-squared determinant identity to avoid subtracting
almost equal floating-point numbers at tiny gaps. Six independent tests cover
orthogonal columns, exact aliases, monotone noise gain, a small-gap asymptotic
and a direct Gram calculation. For 32 samples at 1 Hz and frequency separation
0.001 Hz, σ_min≈0.0410 and the worst-case inverse gain is ≈24.38. This shows
why nominal sub-Nyquist resolution alone says little about noise robustness.

```text
python -B scripts/sasrl_conditioning.py --samples 32 --spacing-hz 0.001 --sample-rate-hz 1
python -B -m unittest discover -s scripts -p 'test_sasrl*.py'
```

This is a two-mode model of public measured signals, not a reconstruction
algorithm or a conditioning certificate for arbitrary spectral clusters.

## Native RNG diagnostics

`crates/core/tests/rng_spectral.rs` samples four consecutive 4,096-bit blocks
directly from `AunsormNativeRng`. A dependency-free radix-2 FFT helper remains
test-only. It evaluates the whole independent real spectrum, including DC and
Nyquist; no mean subtraction can hide stuck/bias defects. Deterministic balanced
periodic controls with periods 2, 16 and 128 must exceed the diagnostic bound,
even though their means are exactly zero.

For independent unbiased ±1 bits, a conservative Hoeffding/union bound across
B bins is E=4N log(4B/α). Each native block uses α=10⁻⁸, so the union across
four blocks is at most 4×10⁻⁸ under that reference model. This loose threshold
catches gross defects; passing is not an entropy estimate or proof of
unpredictability. The FFT is checked against an independent direct DFT,
analytical modes and Parseval's identity, with finite-input/work-size guards.

The diagnostic deliberately differs from
[NIST SP 800-22's spectral test](https://csrc.nist.gov/pubs/sp/800/22/r1/upd1/final),
which has its own reference statistic and sample-size guidance. NIST also
[announced a revision](https://www.nist.gov/news-events/news/2022/04/decision-revise-nist-sp-800-22-rev-1a)
to clarify appropriate use. No new NIST certification or entropy claim follows
from these regression tests.

## Measured telemetry cadence and PCM window experiments

`scripts/sasrl_telemetry.py` consumes JSON captures of decoded gauge frames with
explicit provenance, one connection context and a selected gauge name. It is not
a wire decoder or authenticator. Each capture has `source`, `connection_id`,
`metric`, `expected_interval_ms` and `records`; each record supplies the same
`connection_id` plus a `frame` using the existing version-1/channel-0 JSON shape.
Mixed contexts, absent/ambiguous gauges, duplicate JSON fields and nonfinite
values are rejected. Only gauges are supported; cumulative counters need separate
reset/rate semantics and must not be treated as stationary gauges implicitly.

The current server's `TELEMETRY_INTERVAL` is five seconds (nominal sample rate
0.2 Hz, Nyquist 0.1 Hz), with `MissedTickBehavior::Delay` and wall-clock timestamps.
Actual captured times can drift, jump or skip slots. The diagnostic measures
sequence gaps, wrap, duplication/reordering, interval error and cumulative phase
error against the declared lattice. A user tolerance is reported separately:
jitter that meets the tolerance still blocks an exact-grid FFT. Missing values
are never filled. Millisecond timestamps can hide finer physical jitter, so this
eligibility check does not prove a physical bandlimit or anomaly model.

For eligible power-of-two captures it reports every one-sided FFT bin, including
DC/Nyquist, and full-band Parseval accounting. Tests compare it to a separate
quadratic DFT and analytical signals. `scripts/data/sasrl-telemetry-uniform.json`
and `sasrl-telemetry-jitter.json` are labeled synthetic controls, not live service
captures. Real measured connections are still required before production use.

`scripts/sasrl_pcm.py` is a standard-library mono PCM S16LE WAV laboratory with
bounded RIFF/chunk/sample parsing, independent standard-library WAV interoperability
and a parser fuzz entry point. It keeps identity/integer-upsampled lattice samples
exact and preserves constant signals, including the explicit reflected boundaries.
Noninteger rate conversions do not claim that every original sample time appears
on the output lattice. Downsampling applies a low-pass sinc before selecting the
new lattice; preserving every original value there would contradict anti-aliasing.

The filter multiplies sinc by a Gaussian and a remote smooth compact taper,
normalizes DC gain per rational phase and rejects coefficient L1 gain above four.
Supported rates are 8/16/24/32/44.1/48/96/192 kHz, at most 192,000 input/output
samples and ten million conservative tap evaluations per conversion. Output
length is the ceiling of the duration/rate ratio. PCM quantization uses nearest
even rounding plus saturation, with clipping counts in CLI output. Source files
and existing output files cannot be replaced by the conversion command.

Measured controls exposed excessive 20 kHz attenuation at 44.1 kHz in the first
narrow Gaussian. The default refined profile widens sigma from 8 to 32 lattice
units, expands support from 40 to 160 and places the downsampling cutoff at 95%
of output Nyquist (baseline: 90%). Both profiles remain explicit, bounded offline
experiments. The same 18 quantized 96 kHz tones and two output rates were rerun:

| Control | Baseline | Refined |
| --- | --- | --- |
| 20 kHz -> 44.1 kHz, interior error vs ideal tone (RMS) | 0.2042548 | 0.0000039057 |
| 24 kHz -> 48 kHz, observed output/input RMS (dB) | -57.475 | -136.139 |
| Maximum coefficient L1 gain, 44.1 kHz phases | 2.06242 | 2.62085 |
| Total tap evaluations for the 18 controls | 12,748,275 | 48,851,208 |

Reports `docs/research/sasrl-signal-reproduction.json` (baseline) and
`sasrl-signal-refined-reproduction.json` (refined) retain all frequencies, input
and output PCM hashes, peak/clipping information, parameters and edge exclusions.
These are discrete tone checks, not a universal stopband certificate. Above-cutoff
output RMS can contain retained low-frequency quantization components; it is not
solely the original carrier's response. Excluded edges do not characterize
transients. The refined filter needs roughly 3.82 ms of future source context for
96 -> 44.1 kHz, versus roughly 1.01 ms for the baseline, before a streaming
implementation can emit equivalent interior samples.

Reflection is an explicit offline edge convention, not loss recovery. Applying
the converter independently to each 10 ms frame changes boundary transients;
production needs a history/lookahead buffer, continuity checks, jitter/loss
policy and authenticated/decrypted source frames. It must never reconstruct
missing encrypted shards or authenticated audit events.

```text
python -B scripts/sasrl_telemetry.py scripts/data/sasrl-telemetry-uniform.json --spectrum
python -B scripts/sasrl_telemetry.py scripts/data/sasrl-telemetry-jitter.json --tolerance-ms 5 --spectrum
python -B scripts/sasrl_pcm.py input.wav --rate 44100 --filter-profile refined --output converted.wav
python -B scripts/sasrl_signal_reproduce.py --filter-profile baseline --output new-baseline.json
python -B scripts/sasrl_signal_reproduce.py --filter-profile refined --output new-refined.json
```

The reproduction script preflights the entire fixed tone run under a separate
60-million-evaluation cap. Regressions include a nonzero-phase Nyquist control
so an accidentally zero sampled sine cannot hide aliasing, exact signed PCM
extremes, independent WAV decoding, loss/jitter/drift, sequence wrap, malformed
input and source/output protection. `fuzz/sasrl_signal_stdin.py` exercises the
bounded WAV and capture parsers; unexpected errors remain failures.

## QUIC sample-lattice and exact transport revision

The paper makes the sampling lattice and reconstruction assumptions explicit.
Applied to the existing 96 kHz audio path, that motivated checking the transport
contract at both encode/decode boundaries rather than relying on a constructor
that public fields and deserialization can bypass. Invalid profiles, fragment
indices, channel/payload mismatches, trailing bytes and nonfinite metric values
now return errors. Histogram +infinity remains valid for Prometheus' final bucket;
NaN and -infinity do not. Existing wire fields and channel numbers are unchanged.

The new `QuicDatagramV1::from_pcm_frame` and `reassemble_pcm_frame` helpers
split/reassemble an exact 1920-byte mono S16LE/960-sample frame. They handle reorder
and wrapping sequences, check full fragment sets, and reject duplicates, losses
and mixed stream/timestamp/sequence bases. They do not interpolate missing data.
Encrypted shard contents remain opaque; plaintext helpers run only after envelope
authentication/decryption. Callers must isolate connections/sessions and bind
fragment metadata to authentication, e.g. AEAD AAD. These helpers are explicit opt-in
APIs; no jitter buffer, network receiver or resampler is implied by their presence.

The already-routed public `/http3/capabilities` endpoint now has an auth OpenAPI
contract, enabled/disabled JSON examples and exact ETag/304 semantics. Disabled
builds return 501. A regression parses the whole document using the existing
production OpenAPI parser and checks the public operation and response profiles.
No endpoint or port was added. AES-GCM nonce construction now uses fixed-size
arrays, eliminating warnings in the independent fuzz dependency graph while
preserving 12-byte native-RNG nonces and existing wire envelopes.

Fourteen targeted datagram tests cover these invariants. Parser fuzz coverage is
available in `fuzz/fuzz_targets/fuzz_quic_datagram.rs` and the stable stdin harness
`crates/server/examples/quic_datagram_fuzz_stdin.rs`; the deterministic runner
`fuzz/quic_datagram_corpus.py` is a bounded smoke corpus, not a sustained
coverage-guided campaign. Final continuation checks are recorded below.

## Public-data ingestion and validation-origin revision

The arithmetic/signal experiments require bounded, unambiguous source ingestion.
A separate dependency audit also found two quick-xml advisories in the existing
endpoint discovery tool. Upgrading quick-xml's patched line would require Rust
1.79; instead the narrow sitemap use is replaced by current roxmltree 0.21.1,
whose published package manifest declares Rust 1.60. This is an engineering
security correction, not a consequence of the SASRL arithmetic theorem.

Source inspection showed that a DOM node limit alone would not bound initial
allocations or per-element duplicate-attribute work. The reader therefore
preflights document bytes, raw '<'/'=' reservation markers, tag bytes, attributes
and nesting before DOM parsing, then enforces a node budget. DTD and external
entity resolution are disabled. It preserves standard/default/prefixed sitemap
namespaces, escaped query characters, CDATA and comments while rejecting
ambiguous/empty/nested locations. The complete limits and API contract are in
`crates/endpoint-validator/README.md`.

All discovery bodies (OpenAPI/HTML/XML) now have a one-MiB decoded-byte ceiling,
including chunked and gzip transfers. Sitemap indexes traverse at most 16
same-origin documents, depth four, eight MiB total and 4,096 unique URLs. Cycles
are deduplicated; unavailable required children fail rather than producing a
partial success. Relative index URLs resolve against the final same-origin
response URL. Cross-origin and URL-credential index locations are refused;
redirect policy also stops authentication/custom headers leaving the origin.

Review found an additional URI parsing issue: removing leading slashes before
URL::join could turn '/http://...' (or special backslash prefixes) into an
absolute target. Every seed/OpenAPI/HTML endpoint is now checked before OPTIONS
or validation requests, and both request sites also enforce the origin and
configured credential scope. Valid relative targets preserve the former base
path resolution. Real local HTTP regressions carry fixture auth/custom headers,
prove valid local requests retain them and verify foreign servers receive zero
requests for index, redirect and path escape attempts.

The reader has `fuzz/fuzz_targets/fuzz_sitemap.rs` and a stable stdin harness
`crates/endpoint-validator/examples/sitemap_fuzz_stdin.rs`. The 257-case
`fuzz/sitemap_corpus.py` run had zero failures, including malformed/hostile resource
controls. This is a bounded smoke corpus; sustained coverage-guided fuzzing
remains required. The independent fuzz target builds without warnings.

Current unsuppressed cargo-audit now reports two vulnerability entries, cryptoki
and RSA, down from the original 17. quick-xml is absent from both lockfiles.
Default cargo-deny still fails on four unmaintained PQC provider diagnostics;
existing ignores are unchanged and no new suppression was added. The separate
fuzz workspace still reports the existing RSA advisory and five unmaintained
warnings. The ordinary/SSE response-budget continuation is recorded below;
the discovery/XML limits alone do not certify every response data path.

## Replay isolation finding

Recent code encodes namespace fields using delimiter concatenation, e.g.
`aud={audience};purpose={purpose};transport={transport}` and grace keys with
`jti=...;sub=...;roomId=...`. The JWT crate also joins scope and JTI using `::`.
These encodings warrant a separate collision audit when fields can contain the
delimiters; optional fields represented by `<none>` also need distinction from
that literal value. Changing persistent replay keys without migration can
reaccept previously consumed tokens. The corresponding `PROD_PLAN.md` task
requires migration design and security regressions before a production change.
This is an engineering finding from commit review, not a theorem of the paper.

## Verification and remaining gates

Verification is recorded below as commands complete. Full security/production
approval remains separate from local implementation evidence. No commit, merge,
release or deployment is performed by this revision.

- Python analytical/input/corpus regression suite: 49 tests passed (18 recovery/loader, 6 conditioning, 14 PCM and 11 telemetry).
- Rust spectral regression suite: 6 tests passed, including real Native RNG.
- Core baseline before the new suite: 58 unit, 3 integration and 19 doc tests passed.
- `cargo clippy --all-targets --all-features --locked -- -D warnings`: passed with zero warnings.
- Full test run initially hit Windows memory mapping error 1455. A single-job retry exposed a pre-existing PQC environment race; the test-only lock/restore fix resolved it. Final `cargo test --all-features --locked -j 1 --no-fail-fast --quiet` passed before the QUIC revision: 564 tests passed, 0 failed, 18 pre-existing tests ignored across 59 suites (including doc tests). Ignored HSM/live-soak/unfinished scenarios are not covered by this result.
- Final `cargo fmt --all -- --check` and `git diff --check` passed. Structured evidence including remaining audit findings is in `docs/research/sasrl-validation-summary.json`.
- Installed `cargo-deny 0.20.2` and `cargo-audit 0.22.2` in a task-local temporary directory. Audit initially reported 17 vulnerability entries. Compatible security updates plus removal of unused `rustls 0.22` first reduced this to 4. The XML replacement removed RUSTSEC-2026-0194/0195, leaving 2: cryptoki (RUSTSEC-2026-0286) and RSA (RUSTSEC-2023-0071). Audit and deny remain failing production gates.
- The latest default `cargo deny` reports four unmaintained PQC provider errors. Earlier feature graphs also reported duplicate socket2 versions; the current default scan does not. Existing `deny.toml` contains RSA/paste ignores; this revision adds no suppressions and the unsuppressed audit records the RSA finding explicitly.
- Patched quick-xml 0.41.0 requires Rust 1.79 and patched cryptoki 0.10.1 requires Rust 1.77 (confirmed from their published package metadata). Neither is a drop-in MSRV-1.76 migration; XML is instead replaced with roxmltree (declared MSRV 1.60). The RSA advisory has no patched upgrade. These require a deliberate provider/MSRV/security design rather than version suppression. QUIC's existing dependency line already requires Rust 1.85 under the experimental feature; a full workspace MSRV reconciliation is still needed.
- Rust toolchain used: 1.90.0. New Rust code uses APIs available at MSRV 1.76; a complete 1.76 dependency build has not been verified here.

Remaining research requirements: independently reviewed finite error bounds,
larger complete spectra, family-specific local Euler corrections, noise and
conditioning experiments, reference smooth-Landau comparison, and a sustained
coverage-guided fuzz run. Live telemetry and streaming audio integration require measured production data
and explicit operational/security contracts rather than mathematical analogy.

Continuation verification (QUIC/PCM revision): 14 targeted codec tests and the
OpenAPI production-parser regression passed. All-target/all-feature clippy passed
with no warnings. The independent fuzz target compiled without warnings; 338
stable stdin corpus cases passed with zero failures. Its separate audit initially
found crossbeam-epoch and RSA; upgrading crossbeam-epoch to 0.9.21 leaves only
RUSTSEC-2023-0071 plus five unmaintained warnings. This does not change the root
workspace's four remaining vulnerability entries. The 24 Python tests passed
again. The final full-workspace run passed 577 tests, with 0 failures and 18 existing
ignored tests across 59 suites, including doc tests; the structured validation
file records this final state. Completed checkbox entries in README/PROD_PLAN/TODO remain intact.

Public-signal continuation verification: all 49 Python regressions passed; 2,086
bounded signal-parser mutation inputs produced no unexpected failure. Both
18-tone profile runs completed within the aggregate work budget with zero output
clipping. CLI capture reports `sasrl-telemetry-uniform-check.json` and
`sasrl-telemetry-jitter-check.json` match the exact hashes of their bundled JSON
input files; only the uniform capture includes a spectrum. The Rust implementation
is unchanged in this continuation, so the previously verified 577-test/clippy
result applies to the same Rust changes. Formatting and diff checks passed again.

XML/origin continuation final verification: 595 Rust tests passed with zero
failures or warnings, and 18 existing ignored tests across 60 suites. Endpoint
validation includes 16 unit tests, 4 existing HTTP tests and 10 new security
HTTP tests. All-target/all-feature clippy passed without warnings. Exact tag-byte
and self-closing-element depth boundaries are covered, in addition to the three
seed/OpenAPI/HTML URI escape sources. No commit/release/deployment was created:
the two remaining audit vulnerabilities and unmaintained PQC gate remain open.

### Endpoint response budgets and explicit partial evidence

The discovery-only limit left ordinary validation using an unbounded `.bytes()`
call. The SSE loop also accepted transfer errors as successful empty/partial
responses and appended an entire chunk before checking its sample limit.
`read_validation_body` now rejects ordinary decoded bodies beyond 1 MiB before
buffer extension, including Content-Length, chunked and gzip transfers. EOF
must be reached under the configured total request deadline. Transfer failures
retain endpoint/method/status and produce `Network`; oversized data produces
`ResponseTooLarge`. Partial data is never parsed as a complete JSON response.

SSE intentionally samples at most 1,024 bytes, with additive optional
`body_sample` metadata and an explicit Markdown statement. Reaching the cap
means only a prefix was inspected; it says nothing about later events or event
syntax. A stream that stalls below the cap fails even if a partial event arrived.
Short streams reaching EOF have no prefix-sampling marker. HEAD and 204/205
responses do not incorrectly require JSON payloads. Eight real local HTTP tests
exercise exact/beyond-limit, known/chunked/gzip, bodyless, SSE prefix, stalled
and reset transfers. Limits constrain retained validator buffers, not temporary
chunk allocation inside HTTP/decompression libraries or server backpressure.
This carries the paper's finite-budget/evidence discipline into ingestion, not
its conjectural arithmetic estimator into authentication.

### Independent elliptic local-Euler reference

`scripts/sasrl_euler.py` counts public finite-field points for pinned integral
Weierstrass models. Source models and label mappings were checked on 2026-10-07:
[Cremona 11a1 = LMFDB 11.a2](https://www.lmfdb.org/EllipticCurve/Q/11/a/2),
[37a1 = 37.a1](https://www.lmfdb.org/EllipticCurve/Q/37/a/1). Their model tuples
are `(0,-1,1,-10,-20)` and `(0,0,1,-1,0)` respectively; the exact discriminants
are `-11^5` and `37`. Curve labels from different databases must not be treated
as interchangeable numeric suffixes.

For odd primes, completing the quadratic in y gives exactly
`#E(F_p)=1+sum_x(1+Legendre((a1*x+a3)^2+4*(x^3+a2*x^2+a4*x+a6)))`.
Characteristic two enumerates all four affine pairs. The point at infinity is
included. Singular models and bad reduction of the supplied model are rejected;
there is no minimal-model search or bad-prime Euler-factor approximation.
The exact Frobenius trace is `a_p=p+1-#E(F_p)`; the finite-field meaning is
also documented by [SageMath](https://doc.sagemath.org/html/en/reference/arithmetic_curves/sage/schemes/elliptic_curves/ell_finite_field.html).

Prime-power logarithmic coefficients use `S_0=2`, `S_1=a_p`,
`S_k=a_p*S_(k-1)-p*S_(k-2)`, so `S_2=a_p^2-2p`, **not** the Dirichlet
coefficient `a_(p^2)=a_p^2-p`. Under `L_unitary(s)=L_E(s+1/2)` the selected
coefficient is `S_k*p^(-k/2)*log(p)`. Exact integer fields are kept separate from
floating normalization/log values. This follows algebraically from the good-prime
Euler polynomial described in [PARI's elliptic-curve documentation](https://megrez.math.u-bordeaux.fr/dochtml/html/Elliptic_curves.html).

Bounds are prime <=100,000, exponent <=32, <=128 distinct rows and aggregate
sum of primes <=1,000,000, checked before point enumeration. Models are immutable
five-integer tuples with bounded coefficients; Boolean/noninteger arguments and
composite field sizes are rejected. CLI outputs refuse overwrite. Model tuples,
source URLs, label mappings and canonical metadata hashes accompany JSON output.

Nine regressions include direct exhaustive `(x,y)` counts for five models in
small fields, independent Newton power-sum identities through exponent 12,
Hasse/normalized bounds, work/type rejection and all eight exact values in the
paper's Section 8.3. The paper's eight exact coefficients match. Its reported
spectral estimates are transcribed separately and **have not been reproduced**:
complete curve-specific zero tables and gamma/pole corrections remain required.
Reports: `sasrl-euler-11a1-reference.json`, `sasrl-euler-37a1-reference.json`, and
`sasrl-euler-paper-reference-check.json` under `docs/research/`.

```powershell
python -B scripts/sasrl_euler.py --curve 11a1 --primes 2 3 5 7
python -B scripts/sasrl_euler.py --curve 37a1 --primes 5 7 --exponent 2
python -B -m unittest discover -s scripts -p 'test_sasrl*.py'
```

Response-budget/oracle continuation verification: 603 Rust tests passed, zero
failures/warnings, 18 existing ignored tests across 61 suites. Full clippy passed
with `-D warnings`; the sitemap fuzz target still builds. Final Python regression
count is 58 (including nine independent elliptic-reference tests). The freshly
built sitemap parser again passed all 257 corpus cases. Production audit/deny,
MSRV reconciliation and sustained fuzz/live sampling gates remain open.

### Volatile replay-grace identity revision

The persistent namespace/`::` encoding remains unchanged because existing
consumed rows cannot be unambiguously decoded. Its concrete transition design
is [replay-ledger-migration-design.md](research/replay-ledger-migration-design.md):
atomic canonical/legacy checks, conservative tombstones, an enforced old-writer
fence, rollback retention, and the limits of already-purged history.

The in-memory QUIC grace identity has no persistent migration burden and is
now a `GraceReplayKey` with explicit fields/optional values. Nonblank JTI values
are not trimmed before identity comparison. Issuer, verified audience and
SHA-256 of the exact normalized signed token are included, so another validly
signed token sharing JTI/subject/room cannot inherit the original token's grace.
The sealed JWT payload serialization is unchanged. Restart may lose grace and
reject a retry, while the persistent consumed-token ledger remains authoritative.

Five direct controls cover delimiter shifts, absent/literal sentinel values,
issuer/audience/token isolation, exact JTI bytes and the expiry boundary. A sixth
async regression uses the actual signer/verifier: the original token succeeds,
its exact retry receives grace, and a differently signed token with the same JTI
is rejected. The expiry test uses a 1 microsecond offset after the exact boundary
because Windows `SystemTime` cannot represent a 1 nanosecond difference.

The audit also identified raw-exp ledger cleanup versus exp+leeway acceptance.
This is tracked as its own revision task; prematurely purged history cannot be
reconstructed from spectral estimates or from the ambiguous legacy key string.

The actual verifier regression exposed an existing functional defect: grace's
store-less verifier was called with `require_jti=true`, so it returned
`MissingJtiStore`. Its signature/claim recheck now opts out of store consumption
only after the primary verifier returns `Replay`; the typed grace constructor
still requires a nonblank JTI. Acceptance additionally rechecks the authoritative
active-token ledger. Revocation/expiry or ledger errors fail closed. The real
regression registers the signed token through the ordinary ledger API, proves
exact retry acceptance, rejects a different signed token sharing JTI, revokes
via the normal API and proves the original token's retry is then rejected.

### Consumed-JTI retention through leeway

Two actual store regressions reproduced the early-cleanup bug before fixing it:
`purge_expired` removed a consumed token already accepted within leeway, in both
in-memory and SQLite stores. The verifier now writes new consumption expiry as
`exp + its leeway + 1 second`, using checked `SystemTime` arithmetic. The extra
second preserves the inclusive acceptance boundary under SQLite's floor-to-second
storage. Claims/wire expiration and verifier acceptance rules are unchanged.
No-expiry records still have no expiry. Overflow produces `TimeConversion`.

The tests use real Native RNG keys and signatures, verify consumption inside
leeway, purge at the exact decoded-exp-plus-leeway boundary and still receive
`Replay`. SQLite closes/reopens the WAL database before replay verification.
The in-memory test then purges after the guarded deadline and receives `Expired`
from the verifier rather than accepting a stale token. An overflow control is
included. No mock store or sleeping at a precision boundary is needed.

This improves new records without claiming to restore already-purged history
or silently rewriting existing raw-exp records. All workers sharing a store must
use a reviewed maximum retention/acceptance policy; changing leeway after records
expire cannot recover their consumption. Legacy retention/drain and the persistent
namespace migration remain separate open tasks.

Replay/grace continuation final verification: 612 Rust tests passed,
0 failures/warnings, 18 existing ignored tests across 61 suites. Final all-target/
all-feature clippy passed with `-D warnings`. The final renamed JWT tests passed
28/28; both independent fuzz targets still build without warnings. Sealed
`JwtPayload` fields compare identically to HEAD, and all 178 completed plan
checkbox entries remain intact. Persistent key encodings/legacy rows are not
migrated and no commit/release/deployment was created. Existing two audit
vulnerabilities and unmaintained PQC gates remain open.

### Fixed-budget grace cache and scope/deadline isolation

The timestamp-only tracker used each calling request's grace duration when
pruning all entries. A long retry could extend a prior acceptance's window,
while a short request could remove other still-live records. The cache also
retained unbounded variable-size claim strings. `GraceReplayTracker` now stores
at most 4096 fixed-size `GraceReplayId` keys and `GraceAcceptance` values, with
per-record accepted-at and expires-at. A retry must satisfy both the recorded
deadline and its own requested limit. Re-recording a live identity does not
refresh the original deadline; live records are never evicted for admission.
Capacity exhaustion refuses the new grace record, preserving the ordinary
consumed-token/replay decision. Expired entries free capacity. Zero grace,
checked time overflow and clock rollback fail closed.

The 32-byte retained ID is SHA-256 over a versioned domain, the signed-token
digest, actual verification-scope digest and typed claim/context fields. Every
string uses a presence tag and u64 little-endian byte length; None differs from
empty/sentinel values. The actual scope has its own domain and typed audience,
request-purpose and transport encoding. It is deliberately distinct from the
claim-resolved purpose. This protects, for example, a no-purpose verification
with disabled grace from inheriting grace later recorded for an explicit-purpose
scope using the same token. Delimiter collisions in the existing persistent
namespace do not become grace identity collisions. Fingerprint separation relies
on SHA-256 collision resistance, not mathematically exact string injection into
32 bytes. Text hashing occurs before taking the global mutex; only fixed-size
identity/map operations and bounded pruning run under that lock.

Thirteen tracker/context controls include two actual Native-RNG signer/verifier
and ledger flows: exact-token retry with revocation, and separately consumed
request scopes with denied grace inheritance. The pure tracker controls cover
recorded/ requested deadline intersection, idempotent live records, exact expiry,
zero/overflow/rollback, None/default/delimiter scope distinctions and admission of
4096 records followed by refusal without eviction and reuse after expiry.
The cap limits retained cache state, not the whole HTTP stack's temporary memory
or per-request work. No live-worker throughput or distributed cache availability
claim is made; the tracker is process-local and needs operational load review.

### Expanded MSRV evidence

Offline `cargo metadata --all-features --locked --filter-platform
x86_64-pc-windows-msvc --format-version 1` confirms the workspace still declares
Rust 1.76 but **30 dependency packages declare a higher version**. The findings
are not limited to experimental QUIC or a potential cryptoki upgrade: core's
Argon2 path currently resolves base64ct 1.8.3 (Rust 1.85), shared time 0.3.47
requires 1.88, and activated metadata includes higher-MSRV IDNA/ICU, compression,
selectors and benchmark dependencies. 136 packages have no declared MSRV.
`docs/research/msrv-dependency-audit.json` records exact versions and shortest
workspace reachability paths, including available normal/build/dev edges.

This is declared metadata, not a completed Rust 1.76 build or proof that each
available edge compiles under every command. Missing metadata does not imply
compatibility. Security-clean compatible pins/provider replacements and actual
1.76 default/all-feature target checks remain necessary. In particular, blindly
pinning an older QUIC/TLS/parser version can undo already verified advisory
remediation. No workspace rust-version declaration was raised to mask the drift.
The earlier cryptoki/QUIC-only description was incomplete; this evidence expands
that task rather than treating the repository's MSRV contract as verified.

Fixed-budget grace continuation final verification: 619 Rust tests passed,
0 failures/warnings, 18 existing ignored tests across 61 suites. All-target/all-feature
clippy passed with `-D warnings`, and both separate fuzz targets compile without
warnings. Formatting/diff checks pass. Sealed `JwtPayload` fields compare
identically to HEAD and all 178 completed plan entries remain intact. No commit,
release, deployment, persistent-key migration or MSRV policy change occurred.
The existing two audit vulnerabilities, unmaintained providers, newly expanded
MSRV incompatibility evidence and live-load/research prerequisites remain open.


### Bounded experimental streaming PCM continuation

`scripts/sasrl_pcm_stream.py` carries the finite sinc-Gaussian filter across
arbitrary contiguous chunks. The output position uses integer quotient/remainder
of the absolute sample clock; phases are never reset at chunk boundaries.
History retains preceding taps and sufficient EOF reflection context. Future
samples must arrive before affected outputs are emitted; only explicit
`finish(expected_total_samples)` permits the offline right-edge convention.
A mismatched EOF count, gap, duplicate, reordered block or invalid sample
permanently fails the stream. Offsets and EOF counts are caller declarations:
they cannot detect a producer that silently removes data and renumbers it.
Authenticate and isolate source frames before use. Returned prefix samples do
not certify that later continuity or EOF validation succeeds.

Each push accepts at most 4096 normalized samples. The phase-cache upper bound
is checked before construction (250000 taps); all supported rate/profile pairs
use a history budget below 13000 samples. Each call preflights filtering plus
remaining phase construction against 10 million operations. Integer clocks are
bounded at 2^63-1, and no cumulative-duration work cap is mistaken for a retained
memory bound. The WAV CLI separately limits its complete output and aggregate
work; long-lived application use must provide output handling/backpressure.

```powershell
python -B scripts/sasrl_pcm_stream.py input.wav --rate 48000 --block-samples 960 --output stream.wav
python -B scripts/sasrl_stream_reproduce.py
python -B -m unittest discover -s scripts -p 'test_sasrl*.py'
```

The CLI reuses strict mono S16LE WAV parsing, refuses input/output overwrites
and reports hashes, clipping, cache/history, work and lookahead. It processes
offline unauthenticated research data; it is not a live transport endpoint.
No Rust codec, sealed RNG or JWT response field changed in this continuation.

`docs/research/sasrl-stream-reproduction.json` records six comparisons using
960-, 257- and varying 1/7/31/53-sample chunks at 96 -> 44.1/48 kHz. All output
floats and quantized WAV bytes equal the defined offline reference. Independent
960-sample conversion produces boundary RMSE 0.0140232 and 0.00823072 respectively;
independent 257-sample chunk rounding adds 14 and 8 samples respectively. These
measurements use a fixed quantized 1/20 kHz synthetic signal, not universal SNR
bounds. The preflight is 13848000 filter operations; actual filtering uses
13569790, below the 20 million aggregate limit. Kernel construction has separate
per-call/cache bounds. Clipping is zero in this fixture.

The Python suite now has 71 passing tests, including 13 streaming/budget
regressions. A 2768-case WAV mutation corpus covers eight rates, every fixture
truncation and single high-bit byte flip; accepted bounded prefixes compare
streaming/offline outputs exactly. Unexpected post-parse exceptions escape.
`docs/research/sasrl-stream-corpus.json` records its hash and scope. This is
bounded deterministic evidence, not a coverage-guided campaign. The preceding
619-test Rust and warning-free clippy results apply to unchanged Rust sources.
Live authenticated QUIC, loss/jitter, real-time throughput, sustained fuzzing
and backpressure remain open production tasks.


### First compatible MSRV lock revision

Both root and fuzz lockfiles now resolve base64ct 1.6.0 (edition 2021, declared
Rust 1.60), replacing 1.8.3 and 1.8.0 respectively. Its upstream changelog records
the later edition/MSRV increase and alphabet additions; consumers in the current
Argon2/password-hash/PEM graph accept 1.6. No upstream sealed implementation was
edited. Source: [RustCrypto base64ct changelog](https://github.com/RustCrypto/formats/blob/master/base64ct/CHANGELOG.md).
This is a locked application compatibility pin, not a blanket downgrade of
QUIC/TLS/time security patches or a guarantee for regenerated unlocked graphs.

Fresh Windows/all-feature metadata finds **29** higher-MSRV packages (the earlier
30-count section records the pre-pin baseline), with 136 undeclared MSRVs.
`docs/research/msrv-dependency-audit.json` now includes the compatible pin and an
actual Cargo 1.76 check. Rust 1.76 was installed without changing the default
compiler. An initial offline attempt lacked the old Cargo's registry index;
the online retry resolved the graph and rejected rayon-core 1.13.0, which requires
Rust 1.80, before source compilation. The command was
`cargo +1.76.0-x86_64-pc-windows-msvc check -p aunsorm-core --lib --locked`.
Even this library selection resolves benchmark/dev dependencies; it does not
prove an isolated production-only core graph incompatible at source level.
The wider MSRV contract remains unverified and requires further safe pins and
actual complete checks. The install's separate rustup self-update encountered
an existing cargo-miri proxy; Cargo 1.76 itself subsequently ran successfully.

Fresh root audit still reports cryptoki/RSA's two vulnerabilities and seven
unmaintained warnings, while cargo deny still fails its four unmaintained-provider
errors. The separate fuzz audit still reports RSA and five unmaintained warnings.
No new advisory suppression was added. The first post-pin full test attempt ran
out of disk at MSVC linking (LNK1180). Only the resolved workspace's generated
`target/debug/incremental` cache was removed after checking no compiler was
running, freeing about 18.1 GiB; source, lockfiles and evidence were preserved.
The rerun disables incremental compilation to avoid recreating that cache.


Post-pin full Rust verification: 619 passed, 0 failed, 18 existing ignored across
61 suites; all-target/all-feature clippy passed with `-D warnings`. These results
use Rust 1.90 and both are from completed processes after the disk recovery.
The separate fuzz graph's plain Windows `cargo build` attempt failed at linking
the no-main libFuzzer binary (LNK1561, no entry point). Earlier references to fuzz
builds should be read as separate-graph compiler checks, not a proven runnable
coverage-guided engine. The stable stdin harnesses remain the executable
regression path on this host; a supported cargo-fuzz build/run is still required.

Both post-pin stable stdin binaries build without warnings. Their existing
338-case QUIC and 257-case sitemap corpora pass again with unchanged corpus
hashes. Both separate fuzz targets also pass compiler checking without warnings;
these results do not turn the failed plain libFuzzer link into a successful
coverage-guided engine. Formatting and diff checks pass, and all 178 completed
plan entries remain preserved. No commit, deployment or MSRV policy bump occurred.


### Rayon safety and normal-dependency reachability

Upstream Rayon 1.12.0 fixes a Unicode Range<char> surrogate-boundary error that
could produce invalid character values at an exclusive U+E000 endpoint. The
review therefore did not pin older Rayon solely for MSRV. Both lockfiles now
use 1.12.0; the fuzz graph also moves rayon-core 1.12.1 -> 1.13.0. The root
already used rayon-core 1.13.0. The corrected release still declares Rust 1.80,
so the root's higher-MSRV count stays 29. This is a safety correction, not
completion of the compatibility task.
Source: [upstream release notes](https://github.com/rayon-rs/rayon/blob/main/RELEASES.md).

An important correction to the earlier benchmark description: activated
all-feature Windows metadata also contains the **normal** dependency path
`aunsorm-core -> sysinfo 0.29.11 -> rayon 1.12.0 -> rayon-core 1.13.0`.
Sysinfo enables `default`, `multithread` and `rayon`. Criterion is an additional
dev path. The previous shortest available path through Criterion was valid but
not exhaustive; an isolated production graph cannot be assumed to escape Rayon.
Removing only Criterion parallel statistics would not resolve this core MSRV
obstacle. Any sysinfo feature redesign needs actual entropy-source/performance
validation and must preserve the sealed Native RNG implementation.

`scripts/rayon_boundary_probe.rs` is a safe Rust research probe compiled against
the corrected root artifact, identified from its depfile's `rayon-1.12.0` source
path. Its 1536 comparisons cover exclusive/inclusive ranges before, across and
after the surrogate gap, the exact exclusive endpoint and an empty range.
Reference results come from Rust's standard sequential char iterator.
`docs/research/rayon-boundary-reproduction.json` records probe/library hashes.
Known defective versions were not executed. This verifies the corrected host
artifact under Rust 1.90, not an MSRV build or an all-platform safety proof.
No unsafe code or sealed implementation was added or changed locally.

Both fresh audits retain their existing findings (root: cryptoki/RSA plus seven
unmaintained; fuzz: RSA plus five unmaintained). Deny retains its four provider
errors. No new suppression was added and no claim of a clean release is made.

Final Rayon continuation checks: 619 Rust tests passed, 0 failed/warnings,
18 existing ignored across 61 suites. All-target/all-feature clippy and the two
separate fuzz compiler checks pass without warnings. A fresh actual Cargo 1.76
core-library attempt now reports Rayon 1.12.0 requiring Rust 1.80 before
compilation (the previous run reported rayon-core first). Both requirements are
real; their normal sysinfo path is recorded. Root format/probe format/diff checks
pass. All 178 completed plan entries remain intact; no commit or deployment.


### Measured streaming throughput and preserved-value optimization

`scripts/sasrl_stream_benchmark.py` uses a fixed quantized mono 96 kHz
1/20 kHz synthetic input, 16 blocks of 960 samples and three trials for each
of two profiles and three output rates. Preflight reserves 39542976 filtering
operations before fixture work; actual filtering is 38587680. Phase construction
retains its separate per-call/cache bounds. It reports first-push, steady pushes
(excluding the first two), EOF service times, every measured duration, source/code
hashes and host/runtime provenance. Run with:

```powershell
python -B scripts/sasrl_stream_benchmark.py
python -B -m unittest discover -s scripts -p 'test_sasrl*.py'
```

The recorded baseline and optimized runs were dispatched alone after the test
process completed. Unrelated host load, scheduling, power settings and interpreter
remain uncontrolled. `perf_counter_ns` measures monotonic elapsed service time;
fixture preparation and output hashing are outside the push/finish measurements.
Three short trials and 42 steady observations cannot prove worst-case latency.

The baseline exposed repeated per-tap history checks. The optimized engine checks
that the complete ordered tap interval lies in retained history, then indexes
that interval directly. Boundary samples keep the original reflection path.
Tap order, multiplication, `math.fsum`, gain/anti-alias design, lookahead,
per-call limits and explicit EOF requirements are unchanged. All six float64
output hashes match the pre-optimization fixture exactly. The 76-test Python
suite passes, including the independent offline partition/reflection controls
and five new timing/queue/preflight tests.

Measured steady push p95 (nearest-rank; milliseconds):

| Filter profile | Output Hz | Before | After | Observed before/after ratio |
|---|---:|---:|---:|---:|
| baseline | 44100 | 15.802 | 8.959 | 1.76 |
| baseline | 48000 | 15.375 | 6.321 | 2.43 |
| refined | 44100 | 58.024 | 27.298 | 2.13 |
| refined | 48000 | 50.816 | 25.564 | 1.99 |

These are measurements on this host, not promised speedups. Identity-rate timings
vary below about 1.5 ms and did not show a consistent improvement; they are also
recorded. Even baseline 44.1 kHz's first-push maximum is 31.309 ms and creates
modelled startup debt despite a steady p95 below 10 ms. The default refined
profile remains unchanged and exceeds the 10 ms cadence: every measured refined
downsampling push in the derived arrival model finishes after the next nominal
arrival. No lower-quality profile is silently substituted to satisfy timing.

The queue report applies measured push durations to an unbounded single-worker
FIFO with ideal 10 ms periodic arrivals. Its wait/miss/utilization values are a
model, not a deployed queue, measured packet loss or a backpressure policy.
It excludes EOF and all authentication/transport/scheduler overhead. A productive
next step requires native throughput investigation and bounded live-session
scheduling with source authentication, not interpreting modelled queue debt as
recovered media. Reports: `docs/research/sasrl-stream-benchmark.json` (before)
and `docs/research/sasrl-stream-benchmark-optimized.json` (after), including code
hashes and unchanged-output evidence.

This continuation changes Python research code only. The completed preceding
619-test Rust and warning-free clippy results remain evidence for unchanged Rust
sources/locks, not a new Rust run. Formatting/diff checks and preservation of all
178 completed plan entries are checked again; audit/MSRV/coverage-guided and
live-media production gates remain open. No commit or deployment occurred.


### Independent two-mode perturbation measurement

`scripts/sasrl_conditioning_reproduce.py` now measures actual coefficient changes
on a complete uniform grid of 64 complex samples at 64 Hz. Two frequencies are
known in advance. It builds a cancellation-aware two-column complex QR residual
from exp(it)-1 using -2 sin²(t/2) + i sin(t), rather than solving squared-condition
normal equations. Its residual norm squared independently agrees with the stable
Gram determinant from `sasrl_conditioning.py`. Aliases 0/64/128 Hz are rejected,
and QR residuals at or below 1e-12 are explicitly unresolved rather than inverted.

The fixed experiment adds an adversarial perturbation aligned with the weakest
left singular direction. Its represented sample L2 norm is about 1e-7. Clean-fit
roundoff and the noisy-minus-clean coefficient shift are reported separately;
the measured gain uses the represented perturbation, not just its requested size.
The seven gaps run from an orthogonal 1 Hz separation to 1e-6 Hz.

| Spacing Hz | Measured coefficient-noise gain | Shift for ~1e-7 noise |
|---:|---:|---:|
| 1 | 1.000 | 1.0e-7 |
| 0.01 | 77.981 | 7.8e-6 |
| 0.001 | 779.792 | 7.8e-5 |
| 0.000001 | 779791.997 | 0.078 |

Measured/predicted gain ratios remain within about 1e-10 of unity in the fixed
seven rows; independent regression controls require agreement to seven decimal
places. The reported clean-fit error stays below 1.3e-11 here. This evidence
supports the paper's caution: a tiny sample perturbation can produce a large
coefficient error for close modes. It does not prove a general recovery theorem
or supply a typical random-noise distribution, arbitrary-cluster bound, unknown
frequency estimator, real mono PCM inverse, or sub-Nyquist gap recovery.

```powershell
python -B scripts/sasrl_conditioning_reproduce.py
python -B -m unittest discover -s scripts -p 'test_sasrl*.py'
```

`docs/research/sasrl-conditioning-noise-reproduction.json` stores all rows,
represented norms, QR/Gram controls, numerical thresholds and implementation hash.
The Python suite now passes 81 tests, including five new perturbation controls.
No data was authenticated or reconstructed, and no Rust/crypto/runtime endpoint
changed in this continuation. Existing Rust results apply to unchanged sources;
format/diff and the 178 locked completed plan items are checked again. Audit,
MSRV, full curve-specific spectra and live media production gates remain open.


### Envelope-budget and real authenticated PCM controls

The fixed codec's 960-byte shard limit includes opaque encrypted envelope bytes.
Appending an AES-GCM 12-byte nonce and 16-byte tag to the default 960-byte
plaintext shard exceeds that limit. `from_pcm_frame_with_fragment_bytes` now
lets callers reserve the entire envelope first: an even 8..960-byte plaintext
budget is accepted, retaining at most 240 fragments. The existing helper delegates
with 960, preserving its two-fragment output and wire fields. With 28 bytes of
overhead, the 932-byte budget produces three plaintext shards (932, 932, 56);
the complete encrypted payloads are 960, 960 and 84 bytes.

`crates/server/tests/authenticated_pcm.rs` uses actual AES-256-GCM with fresh
Native RNG key/prefix/context material per frame. Nonces combine a fresh 8-byte
prefix with distinct 4-byte shard counters within that test frame. The test
rejects oversized plaintext before encryption and checks actual encode/decode,
authentication/decryption, reordered assembly and sequence wrap. Missing shards
fail; default splitting remains identical across the new delegation.

The test-only AAD domain and fixed 32-byte context prefix precede the canonical
encoded datagram metadata with the opaque payload cleared. Valid structural
mutations of sequence, timestamp, stream ID, fragment index/count, nonce,
ciphertext and tag fail AEAD authentication, as do a different context/key.
Truncated envelopes fail before decryption. This demonstrates a real caller
integration convention; it neither adopts that convention as a production E2EE
protocol nor installs key management, source identity or a replay ledger.
AEAD alone does not reject replay of an earlier valid frame. Production key/nonce
reuse rules, rekeying, authenticated context establishment, frame replay state,
MTU negotiation and live scheduling require separate review and implementation.

```powershell
cargo test -p aunsorm-server --all-features --test authenticated_pcm --locked -j1
cargo build -p aunsorm-server --all-features --example quic_datagram_fuzz_stdin --locked -j1
python -B fuzz/quic_datagram_corpus.py
```

The stable and coverage-guided source harnesses additionally exercise arbitrary
valid even plaintext budgets derived from the first two fixture bytes. Both
separate fuzz compiler checks pass without warnings; the working native stdin
binary's 338-case corpus passes with its unchanged corpus hash. No runnable
coverage-guided engine or sustained campaign is claimed.

Final workspace verification: 622 Rust tests passed, 0 failed/warnings, 18 existing
ignored across 62 suites. All-target/all-feature clippy passed with `-D warnings`.
Formatting/diff checks pass; sealed JwtPayload and completed plan entries remain
unchanged. No dependency, crypto primitive, Native RNG, endpoint, port or wire-field
change was made in this continuation. Existing audit findings and MSRV/live-media
production gates remain open; no commit, release or deployment occurred.


### Real SQLite transition-fence controls

The migration design now has executable research fixtures against the actual
current SqliteJtiStore rather than a reimplementation of its SQL. Six tests on
temporary WAL databases verify: marker-only insufficiency; already-open insert
rejection and reopened startup rejection; expired-cleanup rejection without
losing tombstones; atomic aborted cutover preserving old consumption; rollback
preserving explicitly projected post-cutover consumption; and maximum/permanent
expiry preservation when projections collide.

The compatibility view/trigger fence is installed in a real IMMEDIATE transaction.
The old table and expiry index remain as legacy tombstones. The actual old open
fails with `views may not be indexed`; an initial startup assumption was corrected
from observed SQLite behavior. Already-open old connections fail at the write
triggers. The current server state constructor propagates store-open errors.
A user_version marker alone permits an old store to consume new tokens and is
therefore shown insufficient by a negative control.

The conservative rollback fixture projects canonical fixture rows before an
atomic schema restoration, retains the canonical table, takes the longest finite
expiry and preserves NULL as permanent. A reopened actual legacy store rejects
both pre-cutover and projected post-cutover consumption. Tests explicitly insert
canonical fixture rows; no new canonical verifier or JtiStore API exists yet.
No stored key is decoded into an invented tuple, and no purged history is inferred
from spectral estimates. These fixtures must not be activated as a migration.

Sources and review limits are in `docs/research/replay-ledger-migration-design.md`;
run `cargo test -p aunsorm-jwt --all-features --test replay_schema_fence --locked -j1`.
The actual atomic canonical-consume operation, concurrent-new-writer and process-
crash tests, maximum policy/drain, third-party store fencing, backup/rollout and
security review remain open. This continuation changes tests/docs only and never
opens a live ledger; production identity encoding and sealed structures remain
unchanged.

Final fence continuation verification: 628 Rust tests passed, 0 failed/warnings,
18 existing ignored across 63 suites. All-target/all-feature clippy passes with
-D warnings. `docs/research/replay-schema-fence-validation.json` records fixture
hashes and exact scope. The production JTI store and sealed RNG have no diff
from HEAD; all 178 completed plan entries remain preserved. Formatting/diff
checks pass. Existing audit/MSRV/live transport and security-review prerequisites
remain open; no migration activation, commit, release or deployment occurred.


### Small multi-mode cluster conditioning

The two-mode caution is now complemented by `scripts/sasrl_cluster_conditioning.py`:
a bounded diagnostic of 2..8 known complex Fourier columns on a complete uniform
grid, with 2..512 samples and at most 40 sweeps. It applies direct one-sided
complex Jacobi column rotations rather than forming Gram eigenvalues by
subtraction. A sample-scaled vector-work preflight caps each call at eight million
units; the largest permitted configuration reserves 6897664 units. This is a
conservative vector traversal budget, not a count of CPU instructions or wall time.
Matrix size and transient columns remain bounded.

The method takes its one-sided Jacobi concept from [LAPACK's reference description](https://www.netlib.org/lapack/explore-html/d1/d5e/dgesvj_8f_source.html).
This Python routine is unpreconditioned and does not implement LAPACK's scaled
rotations, pivoting, or relative-accuracy guarantees. Column correlation controls
convergence; a documented binary64 heuristic resolution floor excludes unresolved
columns. Aliases, sub-floor singular values and unfinished sweeps suppress
condition/noise-gain values. Estimated singular values, Frobenius invariant error,
correlation residual and failure status remain visible. The floor is not a
rigorous rank or error certificate.

Independent controls cover DFT orthogonality, the previous stable two-mode
identity, frequency shift/permutation invariance and a three-mode Cauchy-Binet
Vandermonde determinant computed as nonnegative products of sine-square terms.
All ten new controls pass, including maximum configuration, preflight-before-
construction and explicit one-sweep nonconvergence. The complete Python suite
now has 91 passing tests.

At 64 samples/64 Hz, identical nearest spacing of 0.01 Hz gives:

| Known modes | Noise-gain estimate |
|---:|---:|
| 2 | 77.981 |
| 3 | 8329.143 |
| 4 | 955583.974 |

Thus a two-mode gap metric alone does not describe the full cluster. These are
fixed known-frequency complete-grid estimates, not measured real telemetry,
an arbitrary-cluster theorem, unknown-frequency recovery or a real mono PCM
inverse. No missing authenticated event is reconstructed.

`scripts/sasrl_cluster_reproduce.py` retains ten fixed matrices plus a separate
nonconvergence control, reserving all 2442496 sample-scaled work units before
any solve. Optional explicit host verification compares all ten matrices with
NumPy 2.3.5 complex SVD. According to [NumPy's SVD documentation](https://numpy.org/doc/stable/reference/generated/numpy.linalg.svd.html),
that API uses the LAPACK gesdd routine; the local reference is distinct from the
handwritten Jacobi calculation. On these fixtures, absolute singular-value
differences are below 1e-12 and resolved minimum-value relative differences stay
below 5.1e-11. Relative comparisons are deliberately omitted for unresolved rows.
These controls do not prove accuracy on every allowed matrix.

```powershell
python -B scripts/sasrl_cluster_conditioning.py --samples 64 --frequencies-hz 0 0.01 0.02 --sample-rate-hz 64
python -B scripts/sasrl_cluster_reproduce.py
python -B scripts/sasrl_cluster_reproduce.py --verify-numpy
python -B -m unittest discover -s scripts -p 'test_sasrl*.py'
```

The normal diagnostic/reproduction uses only the standard library. --verify-numpy
is explicit and requires that validation dependency; it neither installs a package
nor silently substitutes an unverified result if unavailable. The committed
`docs/research/sasrl-cluster-conditioning-reproduction.json` contains all spectra,
statuses, controls, code hash and host-library comparison results.
This continuation changes Python research/docs only. The preceding completed
628-test Rust/clippy evidence applies to unchanged Rust sources/locks. Formatting,
diff and 178 completed plan items remain intact; existing audit/MSRV/live-media
and migration-review prerequisites remain open. No commit or deployment occurred.


## Observed-time telemetry conditioning continuation (2026-10-07)

The optional `--known-frequencies-hz` path in `sasrl_telemetry.py` evaluates
2..8 known Fourier modes at every actual observed timestamp, capped at 512
positions and a 24-hour span. It subtracts the integer epoch before conversion
to seconds, preserving millisecond differences even near the u64 limit. Matrix
work and phase range are checked before construction; duplicate/reordered
records, nonforward clocks and captures over the matrix limit are explicitly
blocked rather than cropped. Requested frequencies are validated even when
capture ordering prevents the calculation.

These positions describe geometry only: gauge values are not fitted, producer
timestamps/context remain unverified and sub-millisecond jitter is invisible.
Irregular matrices have no single declared Nyquist frequency. Existing cadence,
sequence-loss and exact-grid FFT conditions stay intact; no missing samples are
created. A successfully evaluated matrix can still be unresolved and return no
condition/noise-gain estimate.

The fixed reproduction reserves 62464 sample-scaled work units before any
analysis. A 32-observation control with every second one-second slot missing
produces identical columns for frequencies 0 and 0.5 Hz: the actual geometry
is unresolved, whereas pretending the retained rows occupy consecutive nominal
slots gives noise gain 1. The capture reports 31 missing slots and keeps FFT
blocked. Conversely, one observed timestamp shifted by 1 ms distinguishes the
otherwise aliased 0/1 Hz columns; this says nothing about authenticating a clock
or reliably recovering unknown frequencies.

`docs/research/sasrl-observed-conditioning-reproduction.json` retains all four
controls, input/code hashes, spectra, statuses and independent NumPy complex128
SVD comparisons built directly from relative positions. Absolute singular-value
differences are below 1e-12, with relative minimum-value comparisons applied only
to resolved rows. The complete uniform-matrix report was regenerated after the
shared solver refactor and still passes its independent controls.

```powershell
python -B scripts/sasrl_telemetry.py capture.json --spectrum --known-frequencies-hz 0 0.5
python -B scripts/sasrl_observed_reproduce.py
python -B scripts/sasrl_observed_reproduce.py --verify-numpy
python -B -m unittest discover -s scripts -p 'test_sasrl*.py'
```

All 101 Python tests pass, including large-epoch precision, real CLI invocation,
loss/jitter aliases, invalid requests, explicit matrix blocking and aggregate
preflight. This continuation changes Python/docs only; preceding 628 passed
Rust tests and warning-free clippy apply to unchanged Rust code. Existing audit,
MSRV, live capture and security-review blockers remain open.


The subsequent accepted-input mutation continuation adds
`fuzz/sasrl_observed_corpus.py`: 669 reproducible inputs, 39 accepted decoded
captures, no failures, and a conservative 20894208-unit aggregate matrix-work
reservation before execution. Structured timing/duplicate-sequence/extreme-gauge
mutations supplement high-bit changes and truncations. The signal harness
limits numerical fuzz controls to complete observed captures of at most 64
positions spanning at most 24 hours, without truncating their geometry.
Tests prove preflight occurs before exercising inputs and that an injected
post-parse numerical failure propagates. The final Python suite has 103 passed
tests; deterministic corpus evidence does not establish coverage-guided fuzzing.
Reproduce with `python -B fuzz/sasrl_observed_corpus.py`.


## Zeta analytic-model contract continuation (2026-10-07)

The current arithmetic estimator uses the Riemann zeta pole at 1, gamma factor
Gamma(s/2), trivial zeros -2,-4,... and conjugate positive/negative zero pairs.
It cannot silently apply those terms to a different primitive L-function.
[NIST DLMF 25.15](https://dlmf.nist.gov/25.15) distinguishes principal poles,
entire nonprincipal functions, parity-dependent trivial zeros and the conjugate
character in the functional equation. This motivates the input guard; it does
not independently prove the manuscript's generalized recovery claims.

`ZeroSpectrum.from_bytes` now permits only source, complete_through, ordinates,
ordinate_error_bound and optional l_function fields. An explicit l_function
object must exactly match `zeta_model()` including types: riemann_zeta, degree
1, conductor 1, self_dual true, unshifted normalization, critical-line real part
0.5, order-one pole at 1, Gamma(s/2) and negative even trivial zeros starting at
-2. Unknown fields, missing model fields, duplicate JSON keys and contradictions
are rejected before estimation. Boolean/integer equivalence cannot bypass the
contract. The model's gamma_factor names the gamma term, not the whole completed
function. Existing inputs without l_function remain accepted and are explicitly
labelled implicit_zeta_legacy_input.

CLI reports include the supported model, whether it was declared or implicit,
and analytic_model_verified_from_input=false. These are supplier declarations: a
parser cannot establish that the ordinates belong to zeta, satisfy RH or form a
complete accurately rounded prefix. Primitive complex/non-self-dual spectra and
curve-specific gamma/pole corrections still need separate implementations.

`scripts/sasrl_model_reproduce.py` uses the actual bundled Odlyzko prefix and
compares legacy/explicit numerical output exactly at 3, 10 and 20 for both hard
and weighted modes. All six pairs agree. Nine contradictory analytic fields are
rejected. The report retains both input hashes, supported model and code hash in
`docs/research/sasrl-model-contract-reproduction.json`. The model-aware loader
fuzz entry point also completed 93 seed/high-bit mutation inputs without an
unexpected exception; it remains a deterministic control, not coverage-guided
fuzzing. The full Python suite passes 111 tests, including rejection before CLI
output and accepted CLI output with explicit unverified status.

```powershell
python -B scripts/sasrl_model_reproduce.py
python -B -m unittest discover -s scripts -p 'test_sasrl*.py'
```

This continuation changes the offline Python tools, fuzz harness and
documentation. Rust sources/dependencies are unchanged from the prior 628-test
and warning-free clippy validation. Existing security audit and MSRV blockers
remain open, and no commit, release or production deployment occurred.


## PKCS#11 boundary hardening continuation (2026-10-07)

The dependency follow-up confirmed that patched Cryptoki 0.10.1 declares Rust
1.77.0 in its official cached Cargo manifest. The repository's explicit 1.76
contract prevents silently selecting that line.
[RUSTSEC-2026-0286](https://rustsec.org/advisories/RUSTSEC-2026-0286.html) concerns
CKA_ALLOWED_MECHANISMS decoding in Cryptoki; it remains open on 0.6.2. The local
KMS call requests CKA_EC_POINT, but that observation does not remediate the
dependency or justify suppressing its advisory.

The follow-up found separate local defects: indexing attributes[0] could panic
on an empty provider result, unchecked DER length accumulation/end arithmetic
could overflow, and OCTET STRING parsing ignored trailing data. The new
`crates/kms/src/pkcs11_point.rs` matches complete canonical single/double
wrappings for exactly 32 Ed25519 bytes. It performs no untrusted length
arithmetic or allocation; triple wrapping, indefinite/nonminimal lengths,
truncation, raw points and appended bytes fail. This bound applies to the local
parser after Cryptoki returns; it does not bound upstream provider allocations.
The caller requires exactly one EC point attribute and reports wrong/empty/
ambiguous lists as HSM errors. Canonical single/double formats stay accepted.

Six new tests cover attributes, all truncations, noncanonical/overflow lengths,
payload bytes starting with the OCTET STRING tag and actual Ed25519 signature
verification. All-feature KMS has 17 passed, zero failed and one existing ignored
legacy test. The full workspace now has 634 passed, zero failed and 18 existing
ignored tests in 63 suites. All-target/all-feature clippy with warnings denied
passes; formatting and diff checks pass. No lint/advisory suppression was added.

The same parser source is compiled into `fuzz_pkcs11_point` and the bounded
`pkcs11_point_stdin` example. A direct Rust 1.76 build with warnings denied
passes; 1765 seeded inputs complete without panic, and every accepted input is
checked against its complete canonical encoding. The separate-graph fuzz target
compiler check passes. Neither the direct source build nor seeded corpus proves
full-workspace MSRV compliance, a functioning coverage-guided engine or live HSM
compatibility. Existing unrelated dependency metadata still has 29 above-MSRV
packages. Reports: `docs/research/pkcs11-point-corpus.json` and refreshed
`docs/research/msrv-dependency-audit.json`.

```powershell
cargo test -p aunsorm-kms --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo check --manifest-path fuzz/Cargo.toml --locked --bin fuzz_pkcs11_point
cargo build -p aunsorm-kms --example pkcs11_point_stdin --locked
python -B fuzz/pkcs11_point_corpus.py target/debug/examples/pkcs11_point_stdin.exe
```

The refreshed audit still reports Cryptoki RUSTSEC-2026-0286 and RSA
RUSTSEC-2023-0071. Cargo deny still reports four unmaintained PQC provider errors.
These failed gates, live HSM checks and dependency/MSRV migration remain open.
Completed plan/README/TODO items and sealed Native RNG/JWT response structures
are preserved. No commit, release or deployment occurred.


## Wrapped-seed lifecycle continuation (2026-10-07)

The old ignored PKCS#11 test used module=None, label=None and wrapped_seed=None,
so it could never initialize the actual software-key path. The old test named
strict public-key validation also failed earlier on wrapping configuration and
did not establish hardware strict behavior. They were replaced with accurately
scoped real software wrapping controls; no HSM emulator or provider substitute
was introduced.

The implemented envelope has exactly 12 nonce + 32 seed + 16 GCM tag bytes,
encoded as 80 standard base64 bytes. Decode/decryption rejects size mismatch
before allocating a large decode buffer or processing AEAD. The trimmed
wrapping-key environment text must be 44 base64 bytes decoding to exactly 32.
A Zeroizing fixed 33-byte decode buffer is owned before decoding, so partial
key material is cleaned on decode errors too. Environment key text, decrypted
seed and retained software seed use Zeroizing owners. The KMS dependency
explicitly enables Ed25519 zeroize; a standalone --no-default-features test
proves SigningKey implements ZeroizeOnDrop without another crate's feature
unification. These checks do not inspect freed memory or all OS/AES internal
copies, and configuration/environment ingestion still allocates its input.

Native RNG generates test nonces for actual AES-256-GCM seed encryption with
key-id as AAD. The configured software backend unwraps the real envelope,
signs with Ed25519 and verifies the result against the independent expected
public key in normal and strict software modes. Wrong key-id/key, six
nonce/ciphertext/tag mutations, raw/truncated/oversized material, 31/33-byte
encrypted seeds and invalid wrapping-key inputs fail. Environment changes are
serialized and the prior process value is restored by scope guard. Hardware
strict public-key validation and actual HSM calls remain separate prerequisites.

All-feature KMS now passes 21 tests with none ignored. The full workspace
passes 638 tests with zero failures and 17 existing unrelated ignored tests,
in 63 suites. Final all-target/all-feature Clippy with -D warnings, formatting
and diff checks pass. The invalid software fixture no longer counts as an
ignored hardware prerequisite. Report:
`docs/research/pkcs11-wrapped-seed-validation.json`. Python research code is
unchanged from its 111 passed tests.

```powershell
cargo test -p aunsorm-kms --all-features --locked
cargo test -p aunsorm-kms --no-default-features --locked signing_keys_enable_zeroize_on_drop_without_feature_unification
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
```

The remaining Cryptoki/RSA and unmaintained PQC audit gates are still open;
this change does not replace those dependencies. Full MSRV metadata still has
29 above-baseline packages. Dedicated wrapped-seed decoder fuzz coverage is
tracked as a new revision; it must reuse real crypto while avoiding a new
vulnerable Cryptoki dependency in the separate fuzz graph. No commit, release
or production deployment occurred, and completed plan items remain intact.


## Shared wrapped-seed decoder continuation (2026-10-07)

Production now calls the same `crates/kms/src/wrapped_seed.rs` decoder compiled
by `fuzz_wrapped_seed` and the `wrapped_seed_stdin` example. It decodes into
a fixed 60-byte envelope and authenticates/decrypts directly in a Zeroizing
32-byte seed buffer. No plaintext Vec allocation occurs; errors drop that owner.
The KMS wrapper translates typed failures to key-id-aware configuration errors.
Nonce/seed/tag sizes, AES-GCM algorithm and AAD bytes are preserved, as shown
by all 21 actual KMS tests including signature and tamper controls.

The separate fuzz graph directly uses existing maintained AES-GCM/aead/base64/
zeroize dependencies and does not gain Cryptoki. Locked compiler check and
fuzz-target Clippy with -D warnings pass. The native-nonce fixture uses known
synthetic wrapping-key/seed material, actual AES-GCM and AunsormNativeRng. Before
writing it, the driver confirms exact recovered plaintext. Saved fixture bytes
are `scripts/data/pkcs11-wrapped-seed-native-fixture.bin`; hashes pin its
reproduction. Fixture generation uses exclusive creation and cannot overwrite
an existing file. It is test material, not a production key export.

656 corpus inputs mutate every nonce/ciphertext/tag bit, every encoded high-bit
position, all truncations and AAD/length/base64 variants. The valid input accepts,
and all 655 changed inputs reject. Successful fuzz decodes additionally reject
a different wrapping key and extended AAD. Callbacks bound their full input to
1104 bytes; this is a harness budget, not an assertion that production key-id
ingestion already has the same bound. Reports:
`docs/research/wrapped-seed-corpus.json` and
`docs/research/shared-wrapped-seed-validation.json`.

```powershell
cargo build -p aunsorm-kms --example wrapped_seed_stdin --locked
python -B fuzz/wrapped_seed_corpus.py target/debug/examples/wrapped_seed_stdin.exe scripts/data/pkcs11-wrapped-seed-native-fixture.bin
cargo check --manifest-path fuzz/Cargo.toml --locked --bin fuzz_wrapped_seed
cargo clippy --manifest-path fuzz/Cargo.toml --locked --bin fuzz_wrapped_seed -- -D warnings
```

The full workspace remains 638 passed/zero failed/17 existing ignored in 63
suites. Root and fuzz formatting/diff checks and all-target/all-feature Clippy
with warnings denied pass. The separate fuzz audit still fails on RSA and
five unmaintained warnings; root Cryptoki/RSA and PQC provider gates remain open.
This seeded/compiled evidence does not establish sustained coverage-guided
fuzzing or live HSM compatibility. Full MSRV metadata remains 29 above-baseline
packages. No commit, release or deployment occurred.


## Public-key identity continuation (2026-10-07)

The software PKCS#11 configuration previously ignored public_key when a wrapped
seed was provided. It now validates a supplied key and requires exact equality
with the actual derived public bytes in normal and strict software modes.
Absence preserves existing derivation. Public metadata decoding preflights
44 encoded bytes and uses a fixed 33-byte buffer, requiring exactly 32 decoded
bytes. Invalid/weak Ed25519 points reject before initial storage. This is
configuration consistency, not proof of hardware custody or source provenance.

The hardware signing branch now strictly verifies the returned signature against
the stored selected public key and requested message before returning it.
It releases the hardware-session mutex before that cryptographic verification.
Wrong-key/message, malformed-length and noncanonical-scalar replies become HSM
errors. A supplied public key is not proven to belong to hardware at startup;
response binding is checked on signing. Existing fallback policy is unchanged.
Live vendor/session compatibility and measured response-verification latency
remain required. No mocked hardware implementation was introduced.

`pkcs11_identity.rs` is shared directly with the compiler-checked fuzz target
and stdin driver. Genuine Ed25519 signatures from known synthetic fixtures
exercise each public-key/signature/message bit, all truncations and weak/scalar
controls: 987 inputs, one valid acceptance, 986 expected rejections and no
unexpected failures. Framing and 1024-byte message budget are laboratory input
conventions, not a new network protocol or production message cap. The producer
checks the actual signature before exclusively writing the fixture.

```powershell
cargo test -p aunsorm-kms --all-features --locked
cargo build -p aunsorm-kms --example pkcs11_identity_stdin --locked
python -B fuzz/pkcs11_identity_corpus.py target/debug/examples/pkcs11_identity_stdin.exe scripts/data/pkcs11-identity-fixture.bin
cargo check --manifest-path fuzz/Cargo.toml --locked --bin fuzz_pkcs11_identity
cargo clippy --manifest-path fuzz/Cargo.toml --locked --bin fuzz_pkcs11_identity -- -D warnings
```

Evidence: `docs/research/pkcs11-identity-corpus.json` and
`docs/research/pkcs11-identity-validation.json`. KMS passes 26 tests with none
failed/ignored; workspace passes 643 tests with zero failures and 17 existing
ignored tests in 63 suites. All-target/all-feature root Clippy, target fuzz
Clippy with warnings denied, formatting and diff checks pass. No Cryptoki was
added to the fuzz graph, whose audit still reports RSA plus five unmaintained
warnings. Root Cryptoki/RSA/PQC, full MSRV (29 above baseline), sustained
coverage-guided fuzzing and live HSM gates remain open. Sealed RNG/JWT structures
and completed tasks are preserved; no commit, release or deployment occurred.
