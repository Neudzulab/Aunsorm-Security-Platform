# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Configurable tracing initialisation with optional OpenTelemetry OTLP export
  controlled via `AUNSORM_LOG` and `AUNSORM_OTEL_ENDPOINT` environment bindings
  when the `aunsorm-server` crate is built with the `otel` feature.
### Planned
- Expand automated fuzzing coverage and long-running soak tests.
- Publish extended architectural documentation via mdBook.
- Harden KMS provider integrations with additional conformance fixtures.

## [0.1.0] - 2025-10-07
### Added
- Initial workspace layout with security-focused defaults and lint gates.
- `aunsorm-core` crate implementing Argon2id KDF profiles, EXTERNAL calibration
  binding, deterministic coordinate derivation, and ratchet primitives.
- `aunsorm-packet` crate providing authenticated packet construction, validation,
  and replay protection hooks.
- PQC bridge crate with strict-mode fail-fast semantics and ML-KEM/ML-DSA
  feature toggles.
- CLI, server, and WASM frontends for encryption, ratcheting sessions, JWT/X.509
  flows, and browser bindings.
- Identity crates for JWT, X.509, and KMS interoperability with zeroization of
  sensitive material.
- Comprehensive examples, benchmarks, and initial CI scaffolding for fmt/clippy/test.

### Security
- Enforced `#![forbid(unsafe_code)]` and `#![deny(warnings)]` across all crates.
- Documented strict-mode environment bindings and downgrade protection story.
- Added deterministic calibration identifiers and coordinate digests to prevent
  tampering and mis-binding attacks.
