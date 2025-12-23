# Aunsorm Integration Test Suite

This crate (`aunsorm-tests`) exercises end-to-end and adversarial flows across the platform. Suites mirror major service boundaries so regressions are caught where they would impact production.

## Test coverage map
- **ACME flows:** account lifecycle, order finalization, renewal, and staging compatibility are exercised under `tests/acme_*.rs`.
- **Blockchain integrity:** mock ledger scenarios in `tests/blockchain_*.rs` verify deterministic datasets, retention policies, and tamper detection.
- **Packet/HTTP3 paths:** datagram semantics, calibration endpoints, and packet core roundtrips validate protocol strictness under `tests/http3_*.rs` and `tests/packet_core_roundtrip.rs`.
- **Identity & OAuth:** end-user and client credential journeys live in `tests/identity_flows.rs` and `tests/oauth_rfc_compliance.rs` to ensure RFC 6749 alignment.
- **KMS and RNG:** conformance, soak, and statistical validation are covered in `tests/kms_conformance.rs`, `tests/soak.rs`, and `tests/rng_statistical_validation.rs`.

## Running the suite
- Default run (fastest path once dependencies are built):
  ```bash
  cargo test -p aunsorm-tests
  ```
- HTTP/3 experiments (enable QUIC datagram coverage):
  ```bash
  cargo test -p aunsorm-tests --features http3-experimental
  ```
- Cloud KMS integrations (exercises remote KMS feature gates):
  ```bash
  cargo test -p aunsorm-tests --features "kms-gcp kms-azure kms-remote"
  ```

Feature switches map directly to the crate features defined in `tests/Cargo.toml` and can be combined as needed during CI or manual runs.
