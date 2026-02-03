# ADR 0001: Standardize on AunsormNativeRng for Cryptographic Randomness

- **Status:** Accepted
- **Date:** 2026-02-01
- **Owners:** Crypto Agent
- **Deciders:** Security Team, Crypto Agent Lead

## Context

Aunsorm components require consistent, audited cryptographic randomness across
all crates. Prior usage patterns mixed `OsRng`, `rand::thread_rng()`, and
different external RNG implementations, making it difficult to enforce
compliance, measure performance, and guarantee uniform entropy mixing.
Additionally, production guidance requires avoiding HTTP RNG endpoints due to
latency and availability risks.

## Decision

All cryptographic random number generation must use the shared
`AunsormNativeRng` implementation across every crate. `OsRng` is permitted only
for initial entropy seeding when initializing `AunsormNativeRng`.

## Alternatives Considered

- **Continue mixed RNG usage:** Rejected because it prevents enforcing
  consistent entropy mixing, complicates audits, and introduces performance
  variability.
- **Use HTTP RNG endpoints:** Rejected because of latency overhead, operational
  dependency on network availability, and the inability to guarantee local
  entropy availability in constrained environments.

## Consequences

- **Positive:** Standardized entropy mixing, reduced audit scope, predictable
  performance, and uniform compliance across crates.
- **Negative:** Requires refactoring legacy code and monitoring compliance in
  every new crate.
- **Neutral:** Local initialization still depends on platform entropy sources.

## Implementation Notes

- Update every crate to import `AunsormNativeRng` and remove direct use of
  `OsRng`, `thread_rng`, and external RNGs.
- Ensure tests are the only location where alternative RNGs may be used.
- Track compliance via the Native RNG task in `PROD_PLAN.md`.

## References

- `PROD_PLAN.md` — Native RNG Compliance section
- `AGENTS.md` — Native RNG mandatory policy
