# ADR 0006: Require Placeholder OpenAPI Specs for Planned Services

- **Status:** Accepted
- **Date:** 2026-03-10
- **Owners:** Platform + Documentation
- **Deciders:** Platform Lead, API Lead

## Context

The documentation portal surfaces OpenAPI specs for every microservice to keep
clients aligned with planned capabilities. Some services are still in planning
or early implementation stages, but omitting their specs from the portal causes
confusion and delays integration work.

## Decision

All planned services must ship a placeholder OpenAPI specification that is
linked from the OpenAPI portal. Placeholder specs must clearly label planned or
in-progress endpoints, include service descriptions, and provide example
payloads where feasible.

## Alternatives Considered

- **Only publish specs for running services:** Rejected because downstream
  clients lack visibility into upcoming APIs and documentation parity suffers.
- **Document planned services in README only:** Rejected because the OpenAPI
  portal is the canonical API reference and should remain the source of truth.

## Consequences

- **Positive:** Clients can review upcoming APIs early, and the documentation
  portal remains complete across planned services.
- **Negative:** Placeholder specs require maintenance as services evolve.
- **Neutral:** No runtime impact; documentation-only change.

## Implementation Notes

- Add placeholder specs under `openapi/` for planned services.
- Mark service status as Planned in the OpenAPI README table.
- Promote placeholder specs to full specs when endpoints ship.

## References

- [OpenAPI documentation README](../../openapi/README.md)
- [Production plan](../../PROD_PLAN.md)
