# Aunsorm Production Deployment Plan

**Version:** 0.5.0 → 1.0.0  
**Target Date:** Q3 2026  
**Status:** In Progress (Blocked on External Dependencies)

This document tracks all remaining work required for production deployment.

---

## Critical Security Tasks

### Clock Attestation System
- [ ] Deploy NTP attestation server with real certificate signatures
 - [ ] Provision dual-node NTP cluster with hardware PPS/GPS modules and HAProxy failover
 - [ ] Issue attestation certificates from production CA and rotate signing keys quarterly
 - [ ] Replace development mock signatures with production cryptographic proofs
 - [ ] Set `AUNSORM_CLOCK_MAX_AGE_SECS=30` in production environment
- [x] Document firewall rules and secure management network for attestation hosts (docs/src/operations/clock-attestation-deployment.md)
- [x] Implement automatic clock refresh service (ClockRefreshService integration)
- [x] Configure health checks to monitor clock attestation freshness
- [x] Enforce HTTPS-only refresh endpoints and verifier gating before publishing snapshots
- [x] Document clock attestation server deployment procedures

### Native RNG Compliance
- [x] Aunsorm Native RNG implemented across all crates
- [x] OsRng usage restricted to initial entropy seeding only
- [x] Security audit of HKDF + NEUDZ-PCS + AACM mixing algorithm
- [x] Formal entropy analysis report
- [x] NIST SP 800-90B compliance validation
- [x] Performance benchmarks vs. hardware RNG
- [x] Document external-only policy for HTTP `/random/*` fallback while enforcing native RNG usage internally

### Key Management
- [ ] Implement hardware security module (HSM) integration for KMS
 - [ ] Finalize vendor selection (AWS CloudHSM vs. on-prem Luna SA) and procurement checklist
 - [ ] Implement PKCS#11 abstraction layer with failover to standby HSM cluster
 - [ ] Update Terraform to provision dedicated VPC subnets and security groups for HSM links
- [ ] Key rotation automation with zero-downtime
 - [ ] Implement dual-publish strategy (old+new keys) with gradual traffic shift
 - [ ] Add integration tests covering rotation rollback and cutover monitoring hooks
- [ ] Encrypted backup/restore procedures
 - [ ] Design sealed secret export format with hardware-bound wrapping keys
 - [ ] Schedule quarterly restore drills and capture runbooks in docs/src/operations
- [ ] Multi-signature approval for sensitive key operations
 - [ ] Integrate change-approval workflow with Slack + PagerDuty and store approvals in tamper-proof log
- [ ] Key material never touches disk unencrypted
 - [ ] Audit all services for tmpfs usage and enforce in CI with static analysis rule
- [ ] Implement key expiration and automatic rotation policies
 - [ ] Define per-algorithm lifetime matrix (RSA, Ed25519, AES-GCM) and codify in config schemas
 - [ ] Expose rotation status metrics for alerting (expiring_soon, expired)

### Authentication & Authorization
- [x] Multi-factor authentication (MFA) for admin operations
- [x] Role-based access control (RBAC) enforcement
- [x] OAuth 2.0 refresh token rotation
- [ ] Token revocation webhook notifications
 - [ ] Implement signed webhook payloads with timestamped nonce validation
 - [ ] Add replay protection storage (Redis) with TTL tuned to webhook retry window
 - [ ] Provide webhook delivery monitoring dashboard and SLA alerts
- [x] Session timeout configuration per client type
- [x] Audit logging for all authentication events

---

## Infrastructure Tasks

### Docker & Orchestration
- [ ] Migrate from Docker Compose to Kubernetes
- [ ] Implement Horizontal Pod Autoscaling (HPA)
- [ ] Configure resource limits (CPU/memory) per service
- [ ] Set up liveness and readiness probes
- [ ] Configure rolling updates with zero downtime
- [ ] Implement blue-green deployment strategy
- [ ] Set up Helm charts for deployment automation

### Networking & Load Balancing
- [x] Configure Ingress controller with TLS termination
- [x] Implement rate limiting at gateway level
- [x] Set up DDoS protection (Cloudflare / AWS Shield)
- [x] Configure internal service mesh (Istio / Linkerd)
- [x] Implement circuit breakers for service resilience
- [x] Set up mutual TLS between services

### Database & Persistence
- [ ] Migrate from SQLite to PostgreSQL for production
- [ ] Configure database replication (master-slave)
- [ ] Implement automated backups with point-in-time recovery
- [ ] Set up connection pooling
- [ ] Configure database encryption at rest
- [ ] Implement database migration versioning strategy

### Monitoring & Observability
- [ ] Deploy Prometheus + Grafana for metrics
- [ ] Configure alerting rules for critical errors
- [ ] Set up distributed tracing (Jaeger / OpenTelemetry)
- [ ] Implement structured logging with log aggregation (ELK / Loki)
- [ ] Create operational dashboards for each service
- [ ] Configure uptime monitoring and SLA tracking

### Tooling & CLI
- [x] Harden CLI default server URL inference so HOST-provided port/path/query hints are preserved
- [x] Revize: Honor HOST overrides in dev scripts (start-all/test-all/deploy-gateway-cert)

---

## API & Integration Tasks

### REST API Hardening
- [ ] Implement API versioning strategy (v1, v2, etc.)
- [ ] Add comprehensive input validation
- [x] Implement request/response compression (tower-http katmanları ile tüm HTTP servisleri otomatik müzakere kullanıyor)
- [ ] Add ETag support for caching
- [x] Implement CORS policies
- [ ] Add OpenAPI/Swagger documentation generation

### PQC (Post-Quantum Cryptography)
- [ ] Complete ML-KEM-1024 implementation
- [ ] Add Falcon-512 signature support
- [ ] Implement hybrid classical+PQC modes by default
- [ ] Performance optimization for PQC operations
- [ ] Interoperability testing with other PQC libraries
- [ ] Security audit of PQC implementations

### ACME / Certificate Management
- [ ] Production Let's Encrypt integration testing
- [ ] Implement DNS-01 challenge automation
- [ ] Certificate renewal automation (30 days before expiry)
- [ ] Wildcard certificate support
- [ ] Certificate revocation handling
- [ ] Multi-domain SAN certificate support

### Blockchain Integration
- [ ] Complete Hyperledger Fabric DID registry implementation (user verification required for live Fabric validation)
- [x] Implement chaincode deployment automation
- [x] Add blockchain-based audit trail for sensitive operations
- [x] Implement DID resolution caching
- [x] Configure blockchain network High Availability
 - [x] Define Fabric network topology, org MSPs, and channel policy baselines
 - [x] Provision CA/peer/orderer certificates with rotation runbooks
 - [x] Implement DID registry chaincode CRUD, events, and access controls
 - [x] Add chaincode lifecycle automation (package, approve, commit, upgrade)
 - [x] Build audit trail pipeline (on-chain events → secure log sink)
 - [x] Implement DID resolution cache invalidation and TTL policy
 - [x] Add HA deployment plan for orderers/peers with failover testing
 - [x] Document operational runbooks for Fabric deployment and upgrades

---

## Testing & Quality Assurance

### Test Coverage
- [ ] Achieve >80% unit test coverage
- [ ] Complete integration test suite for all services
- [ ] Add end-to-end test scenarios
- [ ] Implement chaos engineering tests (fault injection)
- [ ] Add load testing (Locust / k6)
- [ ] Implement security regression tests

### Security Auditing
- [ ] Third-party security audit (penetration testing)
- [x] Dependency vulnerability scanning automation
- [x] Revize: Update time crate to address RUSTSEC-2026-0009
- [ ] Replace unmaintained or vulnerable crypto dependencies flagged by cargo-deny (atomic-polyfill, fxhash, pqcrypto-dilithium/kyber, ring 0.16.20) to restore advisory compliance
- [x] Configure `cargo-deny` to fetch the RustSec advisory database via the git CLI fallback so checks succeed in restricted network environments
- [ ] Static code analysis (cargo clippy strict mode)
- [ ] Dynamic analysis (ASAN, MSAN, TSAN)
- [ ] Fuzz testing for all parsers and decoders
- [x] Align fuzz harness base64 dependency with workspace version to reduce version divergence
- [ ] Supply chain security (verify all dependencies)

### Performance Optimization
- [ ] Profile hot paths and optimize (flamegraph analysis)
- [ ] Reduce memory allocations in critical paths
- [ ] Implement connection pooling for all external services
- [ ] Optimize database queries (indexing strategy)
- [ ] Add caching layer (Redis) for frequently accessed data
- [ ] Benchmark against performance SLAs

---

## Documentation & Compliance

### Technical Documentation
- [x] PROJECT_SUMMARY.md - Architecture overview
- [x] README.md - Quick start guide
- [x] Add PROD_PLAN link in README documentation section
- [x] port-map.yaml - Service port mapping
- [x] Revize: Align agent charter references from PLAN.md to PROD_PLAN.md
- [x] Document `devam` command kickoff expectations in agent charter checklist
- [x] Revize: Clarify CLI environment override variables in README quick start (AUNSORM_SERVER_URL/HOST)
- [x] Document Redoc access links in OpenAPI README quick start and service table
- [x] Revize: Replace hardcoded localhost references in OpenAPI landing page and README with host placeholders
- [x] Revize: Remove remaining localhost references from OpenAPI specs and OpenAPI nginx configuration (ref: Revize hardcoded localhost replacements)
- [x] Revize: Update OpenAPI landing page footer link to JWT guide to use the GitHub source URL
- [x] Revize: Add explicit PROD_PLAN task reference guidance in CONTRIBUTING.md
- [x] Revize: Replace localhost examples in JWT_AUTHENTICATION_GUIDE.md with HOST placeholders
- [x] Revize: Add HOST override guidance to OpenAPI README quick start for docs links
- [x] Revize: Add ADR 0002 documenting the path-based API versioning strategy
- [x] Revize: Align CONTRIBUTING validation commands with strict clippy warning handling
- [x] Revize: Consolidate entropy mixing experiment documentation to remove stale TBD placeholders
- [x] Revize: Align CONTRIBUTING branch naming guidance with agent workflow
- [x] Revize: Clarify cargo-deny advisory database fetch expectations in README validation section
- [x] Revize: Add cargo audit command to README validation section
- [x] Revize: Add `.env` HOST and AUNSORM_SERVER_URL example in README quick start
- [x] Revize: Replace localhost defaults in port-map integration URLs with HOST placeholders
- [x] Revize: Expand README API reference section with OpenAPI source and hosted docs entry points
- [x] Revize: Emphasize HOST override to avoid hardcoded localhost in README quick start
- [x] Revize: Align CLI default server URL port with gateway port 50010
- [x] Revize: Add README note to reference PROD_PLAN tasks in PR descriptions
- [x] Revize: Replace remaining PLAN.md references in contributor guidance (CONTRIBUTING.md)
- [ ] API reference documentation (OpenAPI spec)
  - [x] Revize: Document bulk OpenAPI spec validation command in openapi/README.md
- [x] Revize: Mark planned OpenAPI service cards as placeholder specs in the landing page
- [x] Revize: Align OpenAPI landing page quick-start examples with available service specs
- [x] Add placeholder OpenAPI specs for X509 and KMS services to document planned schemas
- [x] Revize: Link placeholder X509/KMS OpenAPI specs from the documentation landing page
- [x] Revize: Add placeholder OpenAPI specs for ID and MDM services and link them from the documentation landing page
- [ ] Architecture decision records (ADRs)
  - [x] Create ADR template and index (docs/architecture/adr)
  - [x] Revize: Add ADR documenting the `devam` agent continuation workflow
  - [x] Revize: Add ADR documenting mandatory PROD_PLAN task references in PR descriptions
  - [x] Revize: Add ADR documenting AGENTS.md scope inheritance and instruction precedence
  - [x] Revize: Add ADR documenting placeholder OpenAPI specs for planned services
- [x] Disaster recovery runbook — documented in docs/src/operations/disaster-recovery-runbook.md
- [x] Incident response playbook
- [x] Production deployment guide
- [x] Revize: Fix typos and formatting in production-fix-instructions.md

### Compliance & Certifications
- [x] SOC 2 Type II audit preparation
- [x] GDPR compliance review
- [x] HIPAA compliance assessment (if applicable)
- [x] ISO 27001 certification preparation
- [x] Document data retention policies
- [x] Privacy policy and terms of service

### Developer Experience
- [x] Contribution guidelines update
  - [x] Documented native RNG compliance, plan alignment, and endpoint/OpenAPI
    update expectations in `CONTRIBUTING.md`
- [x] Code review checklist
  - Documented reviewer gates in `CONTRIBUTING.md`, including RNG compliance,
    documentation updates, and validation suite requirements
- [x] Development environment setup automation (devcontainer)
- [x] Document validation suite (fmt/clippy/test/deny) in README quick start
- [x] CI/CD pipeline documentation (docs/src/operations/ci-cd-pipeline.md)
- [x] Troubleshooting guide for common issues

---

## Operational Readiness

### Incident Management
- [x] Define SLA/SLO targets (docs/src/operations/sla-slo-targets.md)
- [x] Set up on-call rotation schedule
- [ ] Configure PagerDuty / Opsgenie alerts
- [x] Create incident postmortem template (docs/src/operations/incident-postmortem-template.md)
- [ ] Establish change management process

### Backup & Disaster Recovery
- [ ] Implement automated daily backups
- [ ] Test backup restoration procedures
- [ ] Define Recovery Time Objective (RTO) and Recovery Point Objective (RPO)
- [ ] Set up cross-region disaster recovery
- [ ] Document backup retention policies

### Cost Optimization
- [ ] Right-size container resources
- [ ] Implement auto-scaling policies
- [ ] Set up cost monitoring and alerts
- [ ] Evaluate reserved instance pricing
- [ ] Implement data lifecycle management

---

## Version 0.5.0 Milestone Tasks

### Immediate Priorities
- [x] JWT duplicate field fix (serialize with RFC standard names)
- [x] Clock attestation auto-update on server startup
- [x] Native RNG implementation across all crates
- [x] Complete port-map.yaml and documentation restructure
  - README.md service endpoint tree mirrors the latest port-map statuses (gateway, metrics, CLI, RNG deprecation note)
  - PROJECT_SUMMARY.md microservices table verified against port-map allocations
- [x] Version bump to 0.5.0 in all Cargo.toml files
- [x] Archive legacy planning documents (see `docs/archive/README.md` for the historical index)

### Next Sprint (v0.5.1)
- [ ] Kubernetes deployment manifests
- [ ] PostgreSQL migration scripts
- [ ] Prometheus metrics standardization
- [ ] API versioning implementation

---

## Risk Assessment

### High Risk
- **Clock attestation production readiness**: Development mock mode unacceptable for production
- **Database scalability**: SQLite not suitable for multi-node deployment
- **Key management**: No HSM integration means keys vulnerable to container compromise

### Medium Risk
- **Monitoring gaps**: Limited observability for distributed system troubleshooting
- **API versioning**: Breaking changes require coordination with clients
- **Blockchain dependency**: Hyperledger Fabric adds operational complexity

### Low Risk
- **Documentation gaps**: Can be addressed incrementally
- **Test coverage**: Core crypto functions well-tested, integration coverage improving

---

## Approval Gates

Each section requires approval before marking complete:

- **Security Tasks**: Security Team + CTO
- **Infrastructure Tasks**: DevOps Lead + Platform Architect
- **API Tasks**: API Team Lead + Product Manager
- **Testing Tasks**: QA Lead + Engineering Manager
- **Documentation**: Technical Writer + Product Manager
- **Operational Readiness**: SRE Team + VP Engineering

---

## Progress Tracking

**Last Updated:** 2026-01-31  
**Overall Completion:** ~45%  
**Target v1.0.0 Release:** 2026-Q3  

**Completed Milestones:**
- ✅ Native RNG implementation (all crates)
- ✅ JWT/OAuth basic flow
- ✅ Blockchain chaincode automation
- ✅ Clock attestation refresh service
- ✅ 550+ tests passing

**Blocked Items (External Dependencies):**
- 🔴 HSM Integration - Awaiting vendor selection & procurement
- 🔴 Third-party Security Audit - Awaiting budget approval
- 🔴 PostgreSQL Migration - Awaiting DBA resource allocation
- 🔴 Kubernetes Migration - Depends on PostgreSQL completion

**Velocity:** ~8 tasks/week  
**Estimated Remaining:** ~80 tasks  
**Projected Completion:** ~10 weeks (after blockers resolved)
