# CI/CD Pipeline Documentation

This document describes the automated quality gates and workflow triggers for the
Aunsorm repository. The pipeline is implemented with GitHub Actions and mirrors
local developer requirements for formatting, linting, testing, fuzzing, and
security checks.

## Core CI Workflow (`.github/workflows/ci.yml`)

The primary CI pipeline defines the baseline quality gates that must pass before
changes are accepted. It is currently configured with its `push` and
`pull_request` triggers commented out, so runs are executed when enabled in the
repository or triggered manually. The workflow pins the Rust toolchain to MSRV
1.76.0 and uses shared caching across jobs.

### Jobs

- **Lint** (Ubuntu, macOS, Windows): Runs `cargo fmt --all --check` and
  `cargo clippy --all-targets --all-features -- -D warnings`.
- **Tests** (Ubuntu, macOS, Windows): Executes `cargo test --all-features` with
  property testing cases set to 64.
- **Property tests** (Ubuntu): Runs the packet roundtrip property test suite.
- **Documentation** (Ubuntu): Builds Rust docs, generates the mdBook site, and
  uploads the rendered book artifact.
- **Bench/QA matrix** (Ubuntu): Executes quick Criterion benchmarks, fuzz
  smoke-runs, `cargo audit`, and `cargo deny check` depending on the matrix
  entry.
- **PQC PoC fixtures** (Ubuntu): Optional job gated by the
  `ENABLE_PQC_POC` repository variable.
- **HTTP/3 PoC canary** (Ubuntu): Optional job gated by the
  `ENABLE_HTTP3_POC` repository variable.

## ACME Staging Smoke (`.github/workflows/ci/acme.yml`)

The ACME staging smoke workflow runs on `main` pushes, qualifying pull requests,
or manual dispatches. It validates required ACME staging secrets before running
mock and staging account tests for the ACME crate. This workflow is skipped for
forked pull requests without secrets.

## Endpoint Validator (`.github/workflows/endpoint-validator.yml`)

The endpoint validator workflow runs a dedicated validator test suite, boots a
mock API, and executes the CLI endpoint validation command against that mock
service. It produces Markdown/JSON reports as artifacts. The `pull_request` and
schedule triggers are currently commented out and can be enabled when the
validator is ready to run routinely.

## Nightly Fuzz Corpus (`.github/workflows/nightly-fuzz.yml`)

The nightly fuzz workflow is configured for manual dispatch. It installs the
nightly toolchain, warms the fuzz corpus for the packet/session targets, and
minimizes the resulting inputs. Any minimized corpus archive is published as a
workflow artifact for later replay.

## Blockchain PoC (`.github/workflows/blockchain-poc.yml`)

The blockchain proof-of-concept workflow is a manual or variable-gated pipeline
that runs blockchain integrity tests. It can be enabled via the
`BLOCKCHAIN_POC_ENABLED` repository variable or by providing `enable=true` in a
workflow dispatch run.

## Local Developer Parity

Developers are expected to mirror the CI checks locally before opening a pull
request. The required commands are:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features
cargo test --all-features
cargo deny check
```

## Secrets, Variables, and Artifacts

- **Secrets**: ACME staging tests require `ACME_STAGING_DIRECTORY`,
  `ACME_STAGING_ACCOUNT_KEY`, and `ACME_STAGING_CONTACT`.
- **Repository variables**:
  - `ENABLE_PQC_POC` enables PQC fixture validation in CI.
  - `ENABLE_HTTP3_POC` enables the HTTP/3 canary test job.
  - `BLOCKCHAIN_POC_ENABLED` enables blockchain PoC integrity tests.
- **Artifacts**:
  - The mdBook build is uploaded as `aunsorm-mdbook`.
  - Endpoint validation reports are uploaded as `endpoint-validator-report`.
  - Nightly fuzz corpus archives are uploaded when available.
