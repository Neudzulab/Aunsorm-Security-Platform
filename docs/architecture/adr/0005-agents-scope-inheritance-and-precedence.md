# ADR 0005: Enforce AGENTS.md scope inheritance and instruction precedence

- **Status:** Accepted
- **Date:** 2026-02-05
- **Owners:** Platform Agent
- **Deciders:** Agent Leads

## Context

The repository contains multiple `AGENTS.md` files at different directory
levels. Contributors need a consistent rule set for determining which
instructions apply when touching files in nested scopes, and how to resolve
conflicts between repository-level guidance and local agent directives.

## Decision

Agent instructions are applied using hierarchical scope inheritance:

1. Every `AGENTS.md` applies to the full directory tree rooted at the folder
   that contains it.
2. When multiple `AGENTS.md` files apply to the same file, the deepest
   (most-specific) file takes precedence for local conventions.
3. Direct system/developer/user instructions always override `AGENTS.md`
   guidance.
4. Contributors must validate instruction coverage before editing files and must
   keep pull request descriptions aligned with `PROD_PLAN.md` tasks.

## Alternatives Considered

- **Option A: Use only the repository-root `AGENTS.md`.** Rejected because
  crate- and folder-specific workflows require local rules.
- **Option B: Let contributors choose which `AGENTS.md` files to follow.**
  Rejected because it creates inconsistent behavior and review ambiguity.

## Consequences

- **Positive:** Clarifies instruction resolution, reduces conflicts, and
  improves review consistency across multi-agent domains.
- **Negative:** Adds a small upfront step to locate applicable
  `AGENTS.md` files before making changes.
- **Neutral:** This affects contribution workflow and documentation process, not
  runtime behavior.

## Implementation Notes

- Keep this ADR indexed in `docs/architecture/adr/README.md`.
- Continue adding `Revize:` tasks in `PROD_PLAN.md` whenever policy updates are
  introduced after prior completion.

## References

- `AGENTS.md`
- `PROD_PLAN.md`
- `docs/architecture/adr/0004-prod-plan-task-reference-requirement.md`
