# Aunsorm Security Platform

> Calibration-bound cryptography and zero-trust automation delivered as a coordinated Rust workspace.

**Current status:** Coordinating multi-agent sprint alignment
**Owners**
- @ProjectCoordinator — Program governance
- @CryptoAgent — Cryptography and packetization tracks
- @PlatformAgent — Server, CLI, and deployment surfaces
- @IdentityAgent — Identity, certificates, and KMS integrations
- @InteropAgent — Testing, benchmarking, and interoperability
## Overview
- **Problem**: Fragmented security tooling makes it difficult to ship calibration-bound, PQC-ready features without regressions.
- **Solution**: Unify CLI, server, and library crates around a shared calibration + ratchet model with automated compliance gates.
- **Impact**: Enables faster delivery of production-safe features while maintaining audit-ready documentation and acceptance evidence.

## Core Values
- **Security first** — Strict linting, no unsafe code, and binding calibration contexts to every workflow.
- **Transparency** — Cross-agent plans recorded in PLAN.md, ROADMAP.md, and README endpoint trees.
- **Operational discipline** — CI gates enforce fmt, clippy, tests, deny, audit, and fuzz sanity runs.

## Expert Advisors
- **Crypto Guild** (Calibration council): validates PQC posture, ratchet derivations, and Known Answer Test coverage.
- **Platform Readiness Board**: oversees endpoint rollout sequencing and env parity requirements.

## Quality Gates
- **Automated tests** — `cargo fmt`, `cargo clippy --all-targets --all-features`, `cargo test --all-features`, and focused fuzz/bench runs must pass.
- **Peer review** — Domain agent approval required for each milestone touching their scope-specific AGENTS.md.
- **Security scanning** — `cargo deny` and `cargo audit` reports must be clean before merging.

## Objectives & Success Criteria
### Bootstrap coordinated delivery
- **Status**: Planned
- **Progress**: 10%
- **Next keyword holder**: @ProjectCoordinator
- **Success metrics**:
  - PLAN.md roadmap adopted by all agents
  - README endpoint tree synced with crates/server routes
- **Notes**: Requires completion of STEP-AUN-001 through STEP-AUN-003.
### Harden crypto + identity surfaces
- **Status**: Planned
- **Progress**: 5%
- **Next keyword holder**: @CryptoAgent
- **Success metrics**:
  - Calibration/ratchet docs published with diagrams
  - Identity integration tests and Known Answer Tests automated in CI
- **Notes**: Dependent on documentation streams and CI updates landing together.

## Progress Updates
| Date | Completion | Summary |
|------|------------|---------|
| 2025-03-01 | 5% | Plan structure aligned with VibeCO template; legacy requirements preserved for traceability. |
| 2025-03-02 | 8% | Agent-specific milestones drafted; cross-doc sync tasks enumerated. |

## Roadmap
| Milestone | Due date | Owner | Focus |
|-----------|----------|-------|-------|
| Sprint 1 Alignment | 2025-03-15 | @ProjectCoordinator | Plan hygiene, agent checklists |
| Crypto & Identity Docs | 2025-04-05 | @CryptoAgent | Calibration docs, identity KAT automation |
| Platform Endpoint Sync | 2025-04-20 | @PlatformAgent | README/server alignment, deployment notes |
| Interop Validation | 2025-05-10 | @InteropAgent | Benchmarks, fuzz, cross-language harness |

## Reference Links
- **Code**: https://github.com/aunsorm/aunsorm-crypt
- **Docs**: docs/src/
- **Security**: SECURITY.md
- **Compliance**: certifications/

## Additional Notes
- Revizyon kilidi policy remains in effect; new tasks must be appended with `Revize:` references rather than editing locked items.
- PROJECT_SUMMARY.md and PLAN.md should be reviewed together during sprint kickoffs to avoid divergence.
