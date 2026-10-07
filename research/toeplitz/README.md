# Toeplitz extraction: mathematical research for Aunsorm

An offline, executable reference for converting **certified weak-source entropy**
into almost-uniform bits. It does not replace `AunsormNativeRng`, certify a source,
create physical randomness, or demonstrate that Aunsorm is the world's best RNG.
The experiment uses deterministic Python PRNGs exclusively as synthetic fixtures.
Python 3.10+ is required (`int.bit_count`); no third-party dependencies.

## What the mathematics adds

For a source X, min-entropy measures the hardest-to-predict whole-block outcome:

`H_min(X) = -log2(max_x P(X=x))`.

A marginal histogram is insufficient: repeating one fair bit 4096 times gives
perfectly balanced bit marginals but only **one bit** of block min-entropy.
For classical adversary information E, the applicable quantity is the average
conditional min-entropy:

`H_min(X|E) = -log2(sum_e P(e) max_x P(X=x|E=e))`.

Let the n-bit source have a certified lower bound k on this quantity. Choose a
uniform d-bit seed S independent of (X,E), with `d = n+m-1`. Build the binary
Toeplitz matrix `T[i,j] = S[n-1+i-j]`. The output is `Y = T X` over GF(2).
Bits of the integers in this implementation are indexed from the least
significant bit; matrix products use XOR and AND, not real-valued arithmetic.

For this universal hash family, the classical leftover hash bound is:

`TV((S,Y,E), (S,U_m,E)) <= 0.5 * sqrt(2^(m-k))`.

Here TV is half the L1 distance and U_m is independent uniform output. This is
an averaged joint-distribution guarantee including the public seed, **not a
per-fixed-seed guarantee**. The seed can be public without destroying the
statement. Setting `m = k - 2s` gives distance at most `2^(-s-1)` and therefore
at most `2^-s`. The budget API accepts integer k supplied by a source assessment;
it never estimates k from observed balance. Bounds with side information require
that information to be included in the assessment. Quantum source certification
and quantum side-information guarantees are outside this reference's validation.

### Why the family is universal

For any two distinct inputs, let z be their XOR and r the smallest index with
`z[r]=1`. The i-th output linear equation has highest seed index `n-1+i-r`,
with coefficient one. These m indices are distinct. Increasing i gives a
triangular system with m pivots, so the seed-to-output map has rank m. Every
m-bit result therefore has exactly `2^(d-m)` preimages across all seeds.
Consequently the collision probability is exactly `2^-m`.

For fixed E=e, universality bounds the seed-averaged output collision probability
by `2^-m + sum_x P(x|e)^2`. Cauchy-Schwarz bounds TV by half the square root
of `2^m` times that excess. Since `sum_x P(x|e)^2 <= max_x P(x|e)`, averaging
and Jensen's inequality yield the conditional bound above. This proof uses the
actual source distribution and independent uniform seeds, not a test p-value.

## Reproduce

From the repository root:

```bash
python3 -m unittest discover -s research/toeplitz -v
python3 research/toeplitz/experiment.py > /tmp/toeplitz-results.json
diff research/toeplitz/results.json /tmp/toeplitz-results.json
```

The saved report records Python version and hashes. With a different Python
version the version field can differ; compare numerical results and hashes.
The executable takes no physical-source input and publishes no RNG endpoint.

Eight exact tests cover an independent explicit matrix implementation; all 255
nonzero 8-bit differences against all 2048 seeds (each of 16 outputs occurs
128 times); exact public-seed joint distance for a known small source; parameter
validation; and failures of the independence and entropy assumptions. For the
small source with k=2 and m=1, exact TV is 1/8, below the bound sqrt(1/8).
A source-dependent seed explicitly forces the output to zero despite a fair input.
A constant known input produces balanced output marginals with uniform public
seeds while being completely predictable from the seed; the budget rejects it.

## Synthetic experiment, not a security certificate

The known model is IID Bernoulli with probability 0.8 of a one. Under that model,
`k = floor(-4096 log2(0.8)) = 1318`. With s=128 we choose m=1062 bits.
Independent ideal uniform seeds would yield the theorem's per-block bound
`TV <= 2^-129`. Our seeded Python PRNG fixtures are predictable and do **not**
meet those ideal-source assumptions; the theorem does not certify these samples.

| Measurement | Result |
| --- | ---: |
| Synthetic blocks | 1000 |
| Raw bits | 4,096,000 |
| Raw ones | 3,278,275 (80.0360107%) |
| Extracted bits | 1,062,000 |
| Extracted ones | 531,373 (50.0351224%) |
| Output blocks with exactly half ones | 39 of 1000 |

No rejection of blocks, histogram feedback, target-count adjustment or rerolling
is used. The matrix function returns every computed block. Balance illustrates
conditioning but cannot certify unpredictability; both synthetic inputs are
fully reproducible. The theorem is per block: a multi-block claim needs
conditional entropy given prior transcripts and a composition error budget.

## Aunsorm integration prerequisites

1. Collect **raw** samples from an identified physical entropy source, including
   restart datasets and the adversary/environment model. Conditioned OS/CSPRNG
   output is not a substitute for this source assessment.
2. Establish a conservative block min-entropy bound, including dependencies,
   side information, estimator uncertainty and source health tests. Investigate
   the official NIST SP 800-90B IID/non-IID tools; do not assume independence from
   a histogram or a passing statistical battery.
3. Supply an independently justified seed. This example needs 5157 seed bits per
   1062-bit output block. Consuming a fresh private seed each time has **negative
   net expansion**. A public-seed or seed-reuse design needs a justified source
   independence/conditional-entropy model and a composition argument. No such
   design is silently implemented here. Using a CSPRNG seed changes the claim to
   computational security, rather than unconditional information-theoretic security.
4. Validate a separately reviewed production implementation: Python integer
   timing, secret lifetimes and throughput are unsuitable for cryptographic use.
   Toeplitz hashing is not a NIST-approved conditioning component by virtue of
   this theorem; no SP 800-90B compliance claim is made.

**Concrete benefit delivered:** a tested extraction primitive, a conservative
entropy-to-output budget and explicit counterexamples to false RNG claims.
**Current production benefit:** none is claimed; the sealed RNG remains intact.
Real integration needs source data and a reviewed seed model first.

## Sources

- Ma et al., *Postprocessing for quantum random-number generators: entropy
  evaluation and randomness extraction*, https://arxiv.org/abs/1207.1473
  (universal hashing, Toeplitz construction and seed accounting).
- Tomamichel et al., *Leftover Hashing Against Quantum Side Information*,
  https://arxiv.org/abs/1002.2436 (classical bound and stronger quantum results;
  this implementation does not certify a quantum source).
- NIST random bit generation and approved conditioning-component guidance:
  https://csrc.nist.gov/Projects/random-bit-generation/sp-800-90-updates
- Official entropy-assessment implementation:
  https://github.com/usnistgov/SP800-90B_EntropyAssessment

## Repository gates

Python tests and Rust formatting pass. The unchanged workspace still fails
Clippy on the existing manual Default implementation in `crates/x509/src/ca.rs`
and cargo-deny on existing dependency advisories. The default parallel Rust test
run also hit an existing environment-variable race between the PQC strict-mode
tests, which mutate `AUNSORM_STRICT` without synchronization. A serial full-suite
rerun is used to distinguish this race from deterministic failures. The PR remains a draft and
its production-plan task remains unchecked pending review and gate resolution.
