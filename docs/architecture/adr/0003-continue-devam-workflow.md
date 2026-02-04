# ADR 0003: Formalize the `devam` continuation workflow for agent coordination

- **Status:** Accepted
- **Date:** 2026-03-01
- **Owners:** Project Coordination
- **Deciders:** Platform Lead, Project Coordinator

## Context

Aunsorm development spans multiple domain agents who coordinate work through
shared plans, documentation, and gated quality checks. The `devam` command is
already referenced in operational guidance as the trigger for agent sequencing,
but the workflow has not been captured as a formal architectural decision. This
creates inconsistency in how continuation requests are interpreted and can lead
to work starting without first confirming alignment to `PROD_PLAN.md`.

## Decision

We will formalize the `devam` continuation workflow as the standard signal to
resume or advance coordinated agent work. When `devam` is invoked, agents must:

1. Confirm the target task aligns with `PROD_PLAN.md` (create a task if needed).
2. Validate scope ownership against the agent charter and `AGENTS.md` files.
3. Proceed with implementation only after the task is clearly tracked.

## Alternatives Considered

- **Ad-hoc continuation via chat prompts:** Rejected because it leads to uneven
  validation of plan alignment and increases the risk of out-of-scope work.
- **External ticket-only workflow:** Rejected because it adds overhead and
  duplicates tracking already required in `PROD_PLAN.md`.

## Consequences

- **Positive:** Consistent continuation behavior, explicit plan alignment, and a
  clear audit trail in `PROD_PLAN.md` for all new work items.
- **Negative:** Slightly more upfront coordination work before implementation.
- **Neutral:** No changes to technical architecture beyond documentation.

## Implementation Notes

- Keep `docs/src/operations/agent-charters.md` as the operational reference.
- Ensure any new continuation work adds a tracked item in `PROD_PLAN.md`.
- Update ADR index entries as new coordination decisions are made.

## References

- `docs/src/operations/agent-charters.md`
- `PROD_PLAN.md`
