# ADR 0002: Adopt path-based API versioning for public services

- **Status:** Accepted
- **Date:** 2026-02-14
- **Owners:** Platform Agent
- **Deciders:** API Team Lead, Platform Architect

## Context

Aunsorm services are growing in scope, and forthcoming changes (OAuth expansions,
PQC integrations, and deployment automation) will introduce breaking API surface
area over time. Clients need a predictable, discoverable contract so they can
upgrade safely without service interruption. The production plan also calls out
explicit API versioning as a next-sprint deliverable. We need a versioning
strategy that works consistently across HTTP services, OpenAPI specs, CLI
examples, and gateway routing.

## Decision

Adopt **path-based API versioning** as the canonical strategy for all public
HTTP services. Each service will expose endpoints under a `/v{major}/` prefix
(e.g., `/v1/auth/login`). Gateway routing will treat `/v1` as the default stable
track for production traffic.

Version metadata will also be surfaced via response headers:

- `Aunsorm-Api-Version`: the major version that served the request.
- `Deprecation`: optional HTTP header to indicate pending deprecation windows.

OpenAPI specifications will be versioned per major release and stored as
separate documents (e.g., `openapi/auth-service.v1.yaml`). Documentation and
CLI examples must reference the versioned paths explicitly.

## Alternatives Considered

- **Header-only versioning:** Rejected because it is harder to discover, does
  not surface clearly in logs, and complicates caching/CDN behavior.
- **Query-string versioning (`?v=1`):** Rejected because it is easy to omit in
  documentation and can conflict with existing query semantics.

## Consequences

- **Positive:** Clear routing, easy observability, and straightforward OpenAPI
  documentation per version.
- **Negative:** Requires explicit updates in every client and documentation
  example when a new major version is introduced.
- **Neutral:** Gateway routing must maintain multiple versions concurrently,
  which aligns with the existing deployment roadmap.

## Implementation Notes

- Introduce `/v1` routes in the gateway and services without breaking existing
  functionality; add redirects or deprecation notices for unversioned paths.
- Update OpenAPI specs and documentation to include versioned paths.
- Add version-related headers and deprecation messaging in the API response
  middleware.

## References

- PROD_PLAN.md: API & Integration Tasks → REST API Hardening → API versioning
  strategy
