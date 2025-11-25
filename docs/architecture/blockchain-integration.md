# Blockchain Integration

## Purpose
Ledger anchoring complements Aunsorm's audit streams by providing tamper-evident storage for calibration proofs, device enrollment records, and high-value KMS events. The integration is designed to remain optional and pluggable so regulated deployments can select Hyperledger Fabric, Quorum, or other permissioned networks.

## Current Focus Areas
- **Distributed Identity:** Bind JWT, X.509, and KMS artifacts to DID-style records without leaking sensitive material.
- **Immutable Audit Trails:** Anchor KMS, packet processing, and attestation logs to a ledger with deterministic replay protection.
- **Tokenized Assets:** Reuse Aunsorm cryptographic primitives to mint and manage controlled tokens with strict policy gates.
- **Supply Chain Integrity:** Couple calibration snapshots with hardware identifiers to validate device provenance end-to-end.

## Compliance Guardrails
- Aligns with eIDAS 2.0, MiCA, DORA, GDPR, and CCPA by minimizing on-chain personal data and preferring hashed/off-chain pointers.
- Audit mappings support SOC 2 evidence collection and ISO 20022 messaging expectations.
- Untrusted authorities are rejected via fingerprint validation; attested timestamps remain mandatory.

## Delivery Expectations
- **Mock ledger interface** for deterministic CI tests in `tests/blockchain/`.
- **Interop harness** for permissioned networks with isolated networking and authenticated RPC configuration.
- **Regulatory review loop** with traceable revisions and documented threat modeling under `docs/security/`.
