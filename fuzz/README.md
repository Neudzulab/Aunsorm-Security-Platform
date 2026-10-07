# Parser fuzz entry points

Run the standard coverage-guided target with cargo-fuzz and a supported toolchain:

```powershell
cargo fuzz run fuzz_quic_datagram
```

The QUIC target checks successful decode/encode/decode semantic equality and
exact complete-PCM split/reassembly for 1920-byte inputs. Malformed packets
return typed errors; panics remain failures. It does not authenticate envelopes.

A stable Windows stdin harness is also available:

```powershell
cargo build -p aunsorm-server --example quic_datagram_fuzz_stdin --locked -j1
python -B fuzz/quic_datagram_corpus.py
```

The bounded deterministic corpus exercises truncation, appended bytes, every
single bit in small telemetry/audio seeds, arbitrary byte strings and exact PCM
frames. It is a regression smoke run, not sustained coverage-guided fuzzing.

The independent fuzz workspace has its own Cargo.lock and dependency graph;
verify it separately with `cargo check --manifest-path fuzz/Cargo.toml --locked`.
That compiler check does not link or run the coverage-guided engine. On this
Windows MSVC host, plain `cargo build` of the no-main libFuzzer target failed
with LNK1561 (missing entry point); use the working stdin harnesses for native
regressions and validate cargo-fuzz separately on a supported toolchain/host.
The SASRL JSON/raw-table stdin harness is `sasrl_recovery_stdin.py`; unexpected
exceptions are not caught.

`python -B fuzz/sasrl_signal_stdin.py` reads a bounded byte input and exercises
RIFF PCM WAV or decoded telemetry-capture JSON validation. Expected malformed
inputs return; assertion failures and unexpected exceptions escape.
Accepted WAVs additionally exercise a bounded 64-sample streaming prefix and
compare every output float against the offline reference. Once parsing accepts
input, numeric/state exceptions propagate. The deterministic 2768-case eight-rate
WAV truncation/bit-flip evidence is in `docs/research/sasrl-stream-corpus.json`;
it does not replace sustained coverage-guided fuzzing.
Analytical and deterministic mutation controls run with:

```powershell
python -B -m unittest discover -s scripts -p 'test_sasrl*.py'
```

Sitemap resource/namespace parsing has `fuzz_sitemap` and a stable harness:

```powershell
cargo build -p endpoint-validator --example sitemap_fuzz_stdin --locked -j1
python -B fuzz/sitemap_corpus.py
cargo fuzz run fuzz_sitemap -- -max_len=1048577
```

The parser performs no requests or entity resolution. Index URL fetching is
separately tested on real local HTTP servers. The stable corpus covers truncation,
bit mutations, DTDs, raw pre-allocation markers, deep tags, attribute/URL limits
and oversized documents. Unexpected panics/timeouts are failures.


Observed-time conditioning controls: `python -B fuzz/sasrl_observed_corpus.py`
preflights 669 deterministic cases against a 32-million aggregate matrix-work
budget. Valid timing/sequence/gauge mutations, high-bit changes and truncations
exercise 39 accepted decoded captures. The signal harness diagnoses the entire
observed capture only when it has at most 64 records spanning at most 24 hours;
larger inputs remain parser/cadence controls, without cropping a matrix.
Geometry does not fit gauge values, fill gaps or enable an otherwise blocked FFT.
Expected parser rejection is caught; post-parse numerical errors propagate.
The report is `docs/research/sasrl-observed-mutation-corpus.json`. These seeded
controls are not a sustained coverage-guided campaign.


PKCS#11 EC point: `cargo check --manifest-path fuzz/Cargo.toml --locked
--bin fuzz_pkcs11_point` checks the shared-source target. The stable driver is
`cargo build -p aunsorm-kms --example pkcs11_point_stdin --locked`; run
`python -B fuzz/pkcs11_point_corpus.py target/debug/examples/pkcs11_point_stdin.exe`
(or the corresponding executable on your platform). It preflights at most
4096 cases/4097 input bytes and exercises 1765 canonical, truncated, full-header
mutation, nonminimal, indefinite, overflow and trailing-data inputs.
The report `docs/research/pkcs11-point-corpus.json` was produced using the same
parser/stdin sources compiled directly by Rust 1.76 with warnings denied.
It proves neither a live HSM round trip nor coverage-guided fuzz execution.
Cryptoki's separate dependency advisory remains open.


Wrapped seeds: `cargo check --manifest-path fuzz/Cargo.toml --locked --bin
fuzz_wrapped_seed` compiles the exact production shared decoder without adding
Cryptoki to this graph. The callback bounds input to 1104 bytes (80-byte encoded
envelope plus at most 1024 bytes of AAD), asserts fixed seed size and rejection
with a different key or extended AAD. Production key-id ingestion is outside
this harness input bound.

Build `cargo build -p aunsorm-kms --example wrapped_seed_stdin --locked`, then
run `python -B fuzz/wrapped_seed_corpus.py target/debug/examples/wrapped_seed_stdin.exe
scripts/data/pkcs11-wrapped-seed-native-fixture.bin`. The recorded native-nonce
fixture uses known synthetic wrapping-key/seed bytes. A new fixture is generated
only with `--generate-fixture` and a non-existing path. The driver checks actual
AES-GCM plaintext against the known seed before emitting that fixture.
656 deterministic inputs include every envelope bit, malformed base64, all
truncations and AAD/length changes: one valid input accepts and all 655 mutations
reject. Report: `docs/research/wrapped-seed-corpus.json`. The separate graph still
has the RSA advisory and five unmaintained warnings; no suppression is added.
Compiler/seeded driver evidence is not a sustained coverage-guided engine run.


PKCS#11 identity response: `cargo check --manifest-path fuzz/Cargo.toml --locked
--bin fuzz_pkcs11_identity` compiles the actual shared verifier without Cryptoki.
The laboratory framing is 32 public-key bytes + 64 signature bytes + up to
1024 message bytes; shorter frames exercise malformed signature lengths. This
framing is a fuzz input convention, not a new network protocol.

Build `cargo build -p aunsorm-kms --example pkcs11_identity_stdin --locked` and
run `python -B fuzz/pkcs11_identity_corpus.py target/debug/examples/pkcs11_identity_stdin.exe
scripts/data/pkcs11-identity-fixture.bin`. New known synthetic fixtures use
`--generate-fixture` with a non-existing path. The producer checks an actual
Ed25519 signature before writing it. 987 fixed inputs cover every public-key/
signature/message bit, all truncations, weak keys and noncanonical scalars.
One valid response accepts and 986 changed responses reject. The target
additionally checks that extending the verified message rejects.
Report: `docs/research/pkcs11-identity-corpus.json`. This is no live HSM test or
sustained coverage-guided engine evidence; RSA/unmaintained audit gates remain.
