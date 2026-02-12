# PagerDuty / Opsgenie Alert Routing Runbook

This runbook defines the minimum production configuration for integrating
Aunsorm services with PagerDuty or Opsgenie.

## Scope

- Incident-triggering alerts from gateway, auth, clock attestation, and KMS.
- Escalation hand-off from on-call engineer to security lead.
- Verification of delivery and acknowledgment flow.

## Service Mapping Baseline

| Aunsorm Service | Alert Source | Severity Mapping | Escalation Policy |
| --- | --- | --- | --- |
| API Gateway (`50010`) | Prometheus Alertmanager | Critical, High, Medium | Platform Primary → Platform Secondary |
| JWT/Auth (`50012`) | Prometheus Alertmanager | Critical, High | Identity Primary → Security Lead |
| Clock Attestation (`50014`) | Prometheus Alertmanager | Critical | SRE Primary → Security Lead |
| KMS (`50015`) | Prometheus Alertmanager | Critical, High | Identity Primary → Platform Secondary |

## PagerDuty Configuration Checklist

1. Create one **Technical Service** per Aunsorm component listed above.
2. Attach the correct escalation policy and time-based schedule.
3. Enable event de-duplication using `service + alertname + instance`.
4. Configure automated incident urgency:
   - `Critical` → high urgency, immediate page.
   - `High` → high urgency, page after 5 minutes.
   - `Medium` → low urgency, notification only.
5. Add maintenance windows tied to approved change windows.

## Opsgenie Configuration Checklist

1. Create one Team Routing Rule per ownership group (Platform, Identity, SRE).
2. Map `severity=critical|high|medium` labels to matching priorities.
3. Configure auto-assignment to active on-call schedules.
4. Enable alert policies for deduplication and suppression during maintenance.
5. Configure outbound webhook for incident timeline archival.

## End-to-End Verification Procedure

Run the following for each service integration key:

1. Trigger a synthetic alert via Alertmanager test route.
2. Confirm alert appears in PagerDuty/Opsgenie within SLA (<60 seconds).
3. Acknowledge from primary on-call account.
4. Re-trigger the same alert fingerprint and verify deduplication.
5. Escalate manually and confirm secondary user receives page.
6. Resolve and verify closure sync to observability dashboard.

## Evidence Collection

For each quarterly audit window, store:

- Integration screenshot or API export of escalation policy.
- Delivery timestamp logs from Alertmanager and incident tool.
- Acknowledgment + escalation timestamps.
- Post-incident link in `docs/src/operations/runbook-retention.md`.

## Completion Criteria for PROD_PLAN.md Task

The `Configure PagerDuty / Opsgenie alerts` task can be marked complete only
when all items below are satisfied:

- Production integration keys are provisioned in secret manager.
- Escalation policies are active and tested for all critical services.
- End-to-end verification procedure is executed and archived.
- Incident response playbook references the active alert routes.
