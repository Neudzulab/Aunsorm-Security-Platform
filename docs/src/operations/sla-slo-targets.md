# SLA/SLO Targets

**Version:** 0.5.1 (Draft)

This document defines baseline service-level objectives (SLOs) and service-level agreements (SLAs)
for Aunsorm services. These targets are intended to align engineering, operations, and security
priorities ahead of production readiness.

## Guiding Principles

- **Security-first availability:** Availability targets must not weaken security controls or
  auditability.
- **Measured, not guessed:** All SLOs rely on telemetry from production-grade monitoring
  (Prometheus/Grafana + alerting).
- **User-impact focus:** Objectives are defined for externally visible behavior (latency,
  availability, and correctness) rather than internal component metrics.

## Availability Targets

| Service Tier | Description | SLO Availability | SLA Availability |
| --- | --- | --- | --- |
| Tier 0 | Security-critical (JWT verification, KMS operations, clock attestation) | 99.95% monthly | 99.9% monthly |
| Tier 1 | Core platform (API gateway, identity, issuance) | 99.9% monthly | 99.5% monthly |
| Tier 2 | Auxiliary services (reporting, analytics, dashboards) | 99.5% monthly | 99.0% monthly |

## Latency Targets (P95)

| Operation | Target | Notes |
| --- | --- | --- |
| JWT verification | ≤ 150 ms | Includes signature validation and claims parsing.
| KMS decrypt/sign | ≤ 250 ms | Measured at API boundary.
| Clock attestation refresh | ≤ 400 ms | Includes upstream attestation validation.
| Gateway routing | ≤ 80 ms | Applies to authenticated requests.

## Error Budget Policy

- **Monthly error budget**: 1 - SLO availability.
- **Burn alerts**:
  - **Fast burn**: 10% budget in 1 hour.
  - **Slow burn**: 30% budget in 24 hours.
- **Policy actions**:
  - Fast burn triggers incident response and freeze on non-critical deploys.
  - Slow burn triggers root-cause analysis and post-incident review.

## Measurement & Reporting

- **Monitoring**: Prometheus for service metrics, Grafana dashboards for SLO tracking.
- **Alerting**: PagerDuty for Tier 0 and Tier 1 services, Opsgenie for Tier 2.
- **Reporting cadence**: Monthly SLO reports circulated to engineering and security leads.

## Change Control

- SLA/SLO updates require approval from the SRE lead and Security lead.
- Any reduction in targets must include a documented risk assessment.

## Next Steps

1. Implement SLO dashboards per service tier.
2. Tie incident tracking to error budget burn alerts.
3. Integrate SLO compliance checks into release readiness reviews.
