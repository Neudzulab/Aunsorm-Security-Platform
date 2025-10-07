# Contributing to Aunsorm

Thank you for your interest in strengthening Aunsorm. This document describes
how to propose changes while preserving the project's security guarantees and
high-quality standards.

## Getting Started
- Ensure you are using **Rust 1.76 or newer**. Run `rustup override set 1.76.0`
  in the repository root if needed.
- Install the required tooling:
  - `cargo fmt`, `cargo clippy`, and `cargo test` come with Rustup.
  - `cargo-deny`, `cargo-audit`, and `cargo-fuzz` are used in CI; install them via
    `cargo install` if you plan to run the full pipeline locally.
- Enable the recommended Git hooks in `.git/hooks` (a sample `pre-commit` is
  provided under `Legacy.md`).

## Development Workflow
1. Fork the repository and create a feature branch off `work`.
2. Keep pull requests focused; split unrelated changes into separate branches.
3. Update or add tests alongside code changes. Every module must cover both
   success paths and relevant failure cases.
4. Run the full validation suite before submitting a PR:
   ```bash
   cargo fmt --all
   cargo clippy --all-targets --all-features
   cargo test --all-features
   cargo deny check
   cargo audit
   cargo fuzz run packet -- -runs=10000
   cargo bench --no-run
   ```
   Failing commands must be fixed or explained; we treat warnings as errors.
5. Document externally-visible behavior:
   - Update `README.md`, `CHANGELOG.md`, and crate-level `README.md` files when
     API or UX changes occur.
   - Add rustdoc examples for new public APIs.
6. Rebase onto the latest `work` branch before requesting review to keep the
   history linear.

## Coding Standards
- All crates must include `#![forbid(unsafe_code)]` and `#![deny(warnings)]`.
- Prefer constant-time primitives and zeroization for sensitive material.
- Avoid panics in library code; return typed errors using `thiserror`.
- Gate optional functionality behind feature flags as defined in `PLAN.md`.
- Provide descriptive commit messages using the format `component: summary`.

## Testing Expectations
- Unit tests live next to the code they exercise.
- Integration tests should cover cross-crate flows (encryption/decryption,
  session ratchets, JWT/X.509 interop).
- Property-based tests with `proptest` are required for serialization and
  calibration logic to detect edge cases.
- Benchmarks under `benches/` use `criterion` and must remain deterministic by
  seeding RNGs explicitly.

## Reporting Issues
- Use GitHub Issues for bug reports; include reproduction steps and environment
  details.
- Security-sensitive reports must follow the process in `SECURITY.md`.
- Label work items with the responsible agent (`crypto`, `platform`, `identity`,
  `interop`) to aid triage.

## Community Expectations
- Follow the guidelines in `CODE_OF_CONDUCT.md`.
- Respect review feedback and be prepared to iterate.
- Celebrate improvements to clarity, safety, and maintainability—small cleanups
  are welcome when accompanied by tests.

By contributing, you agree to license your work under the Apache-2.0 license and
certify that you have the right to do so.
