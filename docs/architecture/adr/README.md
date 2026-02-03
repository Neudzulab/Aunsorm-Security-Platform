# Architecture Decision Records (ADRs)

This folder stores Architecture Decision Records (ADRs) for Aunsorm. ADRs capture
important architectural choices, the alternatives considered, and the rationale
for the final decision.

## Workflow

1. Copy the template (`0000-adr-template.md`).
2. Increment the ADR number (four digits) and rename the file using a concise
   decision title, e.g. `0001-use-postgresql-for-production.md`.
3. Fill in the sections and update the status as the decision evolves.
4. Reference related tickets, PRs, or documents in the **References** section.
5. Add a brief entry to the index below.

## Index

| ADR | Title | Status | Date |
| --- | ----- | ------ | ---- |
| 0000 | ADR template | Accepted | 2026-01-31 |
| 0001 | Standardize on AunsormNativeRng for cryptographic randomness | Accepted | 2026-02-01 |
| 0002 | Adopt path-based API versioning for public services | Accepted | 2026-02-14 |
