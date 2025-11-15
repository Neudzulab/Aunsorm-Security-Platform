# Legacy Planning Documents

The `docs/archive/` directory preserves planning artifacts that predate the
current production roadmap in `PROD_PLAN.md`. These files are locked for
historical reference so that future agents can understand previous delivery
agreements without altering active scopes.

| Document | Summary | Notes |
| --- | --- | --- |
| [PLAN.md](PLAN.md) | Comprehensive delivery brief covering architecture, feature gates, and sprint rules from the v1.01 program kickoff. | Superseded by `PROD_PLAN.md`; retain for traceability of earlier requirements. |
| [ROADMAP.md](ROADMAP.md) | Legacy roadmap tracking ACME automation, DNS providers, performance targets, and compliance goals. | Use the production plan milestones instead of updating this file. |
| [TODO.md](TODO.md) | Historical sprint backlog and task checklist. | New backlog items belong in `PROD_PLAN.md` or mdBook operational docs. |
| [AGENT-PROTOCOL.md](AGENT-PROTOCOL.md) | Agent-to-agent escalation and review protocol for the original coordination model. | Superseded by `AGENTS.md` hierarchy and `docs/src/operations/agent-charters.md`. |
| [AGENTS-REQUESTS.md](AGENTS-REQUESTS.md) | Intake template for requesting work from other agents. | Retained as an audit trail; current cross-team intake happens through PROD plan tasks. |
| [MICROSERVICES.md](MICROSERVICES.md) | Legacy microservice inventory and dependency notes. | Refer to `PROJECT_SUMMARY.md` and `port-map.yaml` for the authoritative service map. |
| [README.old.md](README.old.md) | Earlier public README used before the port-map alignment. | Keep for historical messaging reference only. |
| [Legacy.md](Legacy.md) | Single-file proof-of-concept implementation that predates the Rust workspace. | Not maintained; do not run in production contexts. |
| [performance_analysis.md](performance_analysis.md) | Archive of legacy benchmark notes for entropy and session operations. | Use `docs/src/operations/native-rng-performance-benchmarks.md` for current measurements. |

> **Reminder:** Archived documents must not be edited when planning new
> features. Instead, add new tasks to `PROD_PLAN.md` and reference the
> relevant modern documentation sections.
