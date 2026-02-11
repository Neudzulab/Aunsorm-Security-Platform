# ADR 0007: Define Completion Criteria for API Reference Documentation

- **Status:** Accepted
- **Date:** 2026-02-10
- **Owners:** Platform + Interop
- **Deciders:** Platform Lead, Documentation Lead

## Context

`PROD_PLAN.md` keeps `API reference documentation (OpenAPI spec)` as an open
documentation milestone while service-level placeholder specifications are
already published. Contributors need explicit criteria for when this parent
task can be considered complete without waiting for every future endpoint.

## Decision

The API reference documentation milestone is considered complete when all of
the following are true:

1. Every service listed in the endpoint tree has a linked OpenAPI spec (full or
   placeholder) in `openapi/README.md`.
2. The OpenAPI landing page documents how to access rendered docs and source
   specs using host-override-safe URLs.
3. Planned services are labeled as placeholder/planned and can be upgraded
   incrementally as endpoints become available.
4. Validation instructions include an explicit command for checking all OpenAPI
   specs before merge.

## Alternatives Considered

- **Delay completion until all services are production-ready:** Rejected
  because documentation progress would be blocked by unrelated delivery
  timelines.
- **Mark complete based on README prose only:** Rejected because readers rely on
  machine-readable specs and rendered docs, not narrative text alone.

## Consequences

- **Positive:** Clear, auditable definition of done for the parent documentation
  task.
- **Positive:** Teams can iterate on service specs independently while keeping
  API docs discoverable.
- **Negative:** Requires maintenance to keep placeholder labeling accurate.

## Implementation Notes

- Keep planned services visible in the OpenAPI service table.
- Use revision subtasks in `PROD_PLAN.md` for incremental improvements.
- Re-open with `Revize:` entries if completion criteria change.

## References

- [Production plan](../../PROD_PLAN.md)
- [OpenAPI docs README](../../openapi/README.md)
- [ADR 0006: Placeholder OpenAPI policy](./0006-openapi-placeholder-spec-policy.md)
