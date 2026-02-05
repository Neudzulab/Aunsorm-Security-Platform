# ADR 0004: Require explicit PROD_PLAN task references in pull requests

- **Status:** Accepted
- **Date:** 2026-02-05
- **Owners:** Platform Agent
- **Deciders:** Agent Leads

## Context

Aunsorm development is coordinated through `PROD_PLAN.md`, but contributors can
still submit implementation changes without clearly identifying which plan task
those changes satisfy. That weakens traceability and slows review because
reviewers must manually map code and docs changes back to production-readiness
items.

## Decision

Every pull request must explicitly reference at least one active `PROD_PLAN.md`
task in the PR description. If a change is a follow-up to a completed item, the
PR must reference a new `Revize:` task instead of reopening the completed task.

## Alternatives Considered

- **Option A: Keep references optional in PR descriptions.** Rejected because it
  does not enforce consistent traceability across agent domains.
- **Option B: Require references only for feature work.** Rejected because
  documentation, compliance, and infrastructure changes also affect production
  readiness and need the same audit trail.

## Consequences

- **Positive:** Improves planning traceability, review efficiency, and audit
  readiness.
- **Negative:** Adds small overhead to PR authoring.
- **Neutral:** Does not change runtime behavior or deployment topology.

## Implementation Notes

- Update contributor guidance to mention explicit `PROD_PLAN.md` task
  references in PR descriptions.
- Add this ADR to the index in `docs/architecture/adr/README.md`.

## References

- `PROD_PLAN.md`
- `CONTRIBUTING.md`
