# SASRL arithmetic reconstruction research

This offline research tool reproduces the **conjectural hard-cutoff** formula
from Oğuzhan Özbay's *Stable Arithmetic Spectral Recovery* manuscript:

\[
\widehat\Lambda_H(n)=1-\frac{2}{\sqrt n}
\sum_{0<\gamma\leq\pi n}\cos(\gamma\log n).
\]

It compares each estimate with von Mangoldt values from an exact sieve and
classifies primes with the fixed threshold `0.75 * log(n)`. Prime powers with
exponent greater than one count as composites. The full weighted Mellin
theorem is **not implemented** here. This is not an RNG, an entropy source,
a cryptographic security test, or a production primality service.

## Reproduce

Python 3.9+ is sufficient; there are no third-party dependencies. From the
repository root, download the external research table explicitly:

```bash
mkdir -p research/sasrl/data
curl -fL https://www-users.cse.umn.edu/~odlyzko/zeta_tables/zeros1 \
  -o research/sasrl/data/zeros1.txt
sha256sum research/sasrl/data/zeros1.txt
```

Pinned SHA-256:

```text
3436c916a7878261ac183fd7b9448c9a4736b8bbccf1356874a6ce1788541632
```

The [publisher's index](https://www-users.cse.umn.edu/~odlyzko/zeta_tables/)
describes the first 100,000 ordinates as accurate within `3e-9`. The validator
only attributes that source and error bound when the entire file hash matches.
Sorting alone does not establish completeness of another supplied table.

```bash
python3 research/sasrl/validate.py \
  --zeros research/sasrl/data/zeros1.txt \
  --output-dir research/sasrl/results/paper

python3 research/sasrl/validate.py \
  --zeros research/sasrl/data/zeros1.txt \
  --block 2:399 --block 10000:12000 \
  --output-dir research/sasrl/results/additional

python3 research/sasrl/scan.py \
  --zeros research/sasrl/data/zeros1.txt \
  --output research/sasrl/results/cutoff_scan.json

python3 -m unittest discover -s research/sasrl -p 'test_*.py' -v
```

Each validator run writes `estimates.csv` with **every** evaluated integer and
`summary.json` with ranges, source/code hashes, Python version, confusion
counts and reconstruction errors. Endpoints of ranges and spectral cutoffs
are inclusive. Overlapping ranges, nonfinite or unordered ordinates, and
insufficient spectral coverage are rejected. The scan publishes all five
fixed offsets, including composite-only errors for both blocks.

## Recorded results

The checked-in summaries were generated with Python 3.12.14 and the pinned
table on 7 October 2026:

| Experiment | Integers | Primes | Composites | Classification errors | RMSE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Seven manuscript blocks | 3,100 | 394 | 2,706 | 0 | 0.11240399 |
| Two additional fixed ranges | 2,399 | 287 | 2,112 | 0 | 0.10912371 |

These are 5,499 distinct selected integers, **not every integer** below 18,149.
Zero classification errors do not imply exact coefficient estimates or a
proof for arbitrarily large integers. The five-point scan has its lowest
RMSE at π in both blocks and their composite subsets; it does not establish
a unique global optimum. Binary64 cosine calculations and `math.fsum` are
used; last-digit platform differences are possible.

## Sensitivity bound

For ordinate errors at most δ, with K retained zeros and J supplied zeros
within δ of the cutoff, the reference implementation reports

\[
|\Delta\widehat\Lambda_H(n)|\leq
\frac{2}{\sqrt n}\bigl(K\log n\,\delta+J\bigr).
\]

The cosine Lipschitz bound controls the K phase changes; at most J terms
can enter or leave the sum. Coverage through the cutoff plus δ is required.
This accounts for input perturbations and cutoff crossings, **not** rounding,
missing zeros, or conjectural reconstruction error. In the recorded 5,499-row
runs J was zero, the maximum bound was about `3.216e-5`, and every threshold
margin exceeded its bound. This conclusion applies only to the stated
ordinate error model.

The arithmetic tests compare sieve output with independent trial division,
verify prime-power handling and inclusive cutoffs, and exercise a cutoff
crossing and malformed/insufficient datasets. They use actual arithmetic,
not a mocked reconstruction implementation.

## Aunsorm scope and validation

This directory has no dependency on the Rust crates and no connection to the
native RNG, key generation, HTTP endpoints, or runtime configuration.
Deterministic zeta data provide no demonstrated fresh entropy. A security
application would require its own threat model and analysis.

`PROD_PLAN.md` tracks the SASRL research task. Local checks passed: seven
Python tests, both recorded numerical runs, the cutoff scan, Rust formatting,
and the all-feature Rust suite (570 passed, 18 existing ignored tests).
The workspace Clippy gate remains blocked by the existing derivable `Default`
implementation in `crates/x509/src/ca.rs`. The dependency gate still reports
existing advisory findings; this change adds no Rust dependencies. The PR is
kept as a draft for review rather than reporting these gates as clean.
