# Security Controls Mapping

**Platform**: KESTREL SOC Platform
**Last updated**: 2026-03-15 (updated for P6 + Detection Rules + Resilience features)
**Scope**: Backend API (`app/`), Frontend (`frontend/src/`), CI/CD (`.github/workflows/`)

This document maps implemented security controls to SOC 2 Type II, ISO 27001:2022, and PCI-DSS v4.0 requirements. Each entry references the specific code path or policy document that satisfies the control.

---

## SOC 2 Type II — Trust Services Criteria

### CC6 — Logical and Physical Access Controls

| Criterion | Control Description | Implementation |
|---|---|---|
| CC6.1 | Restrict logical access based on job responsibility | `app/security/rbac.py` — `require_permission()` enforces role-based access on every endpoint. Roles: `viewer`, `analyst`, `admin`. Permissions mapped per role and verified on each request. |
| CC6.2 | Issue credentials based on authorisation | `app/api/auth.py` — account creation restricted to `admin` role. JWT tokens issued after credentials verified against bcrypt hash. |
| CC6.3 | Remove access when employment changes | `PATCH /auth/users/{id}` with `is_active=false` deactivates accounts. Tokens in flight are invalidated via `TokenBlocklist` (`app/models/token_blocklist.py`). |
| CC6.6 | Implement controls to restrict unintended external access | Security middleware (`app/security/middleware.py`): CORS restricted to allowlist, security headers on all responses (CSP, HSTS, X-Frame-Options). Rate limiting per IP (`app/security/rate_limit.py`). |
| CC6.7 | Restrict transmission of sensitive data to authorised parties | All API traffic requires Bearer JWT. CSRF double-submit protection (`app/security/csrf.py`) on all state-changing endpoints. `HttpOnly`+`Secure` session cookies. |
| CC6.8 | Implement controls to prevent/detect malicious software | SAST (Bandit, Semgrep), SCA (pip-audit, Safety, npm audit), container scanning (Trivy), secret scanning (TruffleHog) run on every PR via `.github/workflows/security.yml` and `dependency-audit.yml`. |

### CC7 — System Operations

| Criterion | Control Description | Implementation |
|---|---|---|
| CC7.1 | Detect/prevent security events in production | Alert ingestion pipeline (`app/core/ingest.py`) feeds SIEM-like alerts. Detection rules engine (`app/core/detection_rules/`) evaluates every ingested event. |
| CC7.2 | Monitor system components for anomalies | Source health monitoring (`app/services/source_health.py`) — per-connector freshness SLOs, error budget tracking, stale-feed alerting. Dashboard freshness indicator (`app/api/dashboard.py` — `ingest_lag_minutes`). |
| CC7.3 | Evaluate security events | Incident management (`app/api/incidents.py`), alert triage workflow (`app/api/alerts.py`), playbook execution (`app/api/playbooks.py`). |
| CC7.4 | Respond to identified security incidents | Playbook SOAR (`app/playbooks/executor.py`, `library.py`), response actions API, evidence attachment (`app/api/evidence.py`). IR runbook approval gate (`app/api/resilience.py` — `approve_runbook_request`, `execute_runbook_request`) enforces dual-control before high-risk SOAR actions execute. |
| CC7.5 | Restore affected infrastructure | Resilience framework (`app/api/resilience.py`) — restore drill records, DR runbooks. `POST /resilience/dr/drills/{id}/run` records simulated RPO/RTO actuals for audit evidence. |

### CC9 — Risk Mitigation

| Criterion | Control Description | Implementation |
|---|---|---|
| CC9.2 | Monitor and assess vendor/third-party risks | Dependabot weekly SCA scans (`.github/dependabot.yml`), pip-audit and npm audit on every PR. Detection rule peer-approval process (`POST /detection-rules/{id}/approve-change`) prevents unilateral changes to detection logic. Secrets rotation policy registry (`GET /resilience/secrets/rotation-check`) surfaces overdue credential rotations as a vendor credential risk indicator. |

### A1 — Availability

| Criterion | Control Description | Implementation |
|---|---|---|
| A1.2 | Protect against availability threats | Background job queue with retries and DLQ (`app/services/job_queue.py`, `app/models/background_job.py`). Source health SLOs with auto-alerting (`GET /sources/health` — freshness seconds, error budget remaining, stale-source detection). DR drill records (`app/api/resilience.py` — `/dr/drills`) with tracked RPO/RTO actuals provide tested restore evidence. |

### C1 — Confidentiality

| Criterion | Control Description | Implementation |
|---|---|---|
| C1.1 | Identify and classify confidential information | Asset CMDB (`app/models/asset.py`) with criticality and owner classification. `POST /assets/{id}/enrich` computes and stores `confidence_score` from telemetry, enabling risk-based prioritisation of high-criticality assets. Evidence legal hold (`app/models/evidence_legal_hold.py`). |
| C1.2 | Restrict access to confidential information | Row-level tenancy registry (`app/api/resilience.py` — `/tenants/workspaces`, `/tenants/isolation-check`) tracks org/workspace boundaries; full data-layer isolation is a P5-8 planned control. Access controlled at API layer by RBAC. Tenant workspace management requires `admin:write`. |

### PI1 — Processing Integrity

| Criterion | Control Description | Implementation |
|---|---|---|
| PI1.1 | Obtain and process inputs completely and accurately | Pydantic request validation on all endpoints — invalid payloads return 422 with structured errors. Detection rule engine validates rule syntax before activation. |

---

## ISO 27001:2022 — Annex A Controls

### A.5 — Organisational Controls

| Control | Description | Implementation |
|---|---|---|
| A.5.14 | Information transfer | API: TLS enforced via `https_only` in SessionMiddleware when not in debug mode. No plaintext transfer paths. |
| A.5.15 | Access control | `app/security/rbac.py` — `require_permission()` on every endpoint. Admin endpoints behind `AdminRoute` in frontend. |
| A.5.16 | Identity management | User model (`app/models/user.py`) with bcrypt hashed passwords, failed-login tracking (`app/models/failed_login.py`), lockout after threshold. |
| A.5.17 | Authentication information | Passwords stored as bcrypt hashes (cost factor ≥12). JWT RSA asymmetric keys (`app/security/auth.py` — `ensure_jwt_keys()`). Session tokens are `HttpOnly`+`Secure`. |
| A.5.26 | Response to information security incidents | Incident lifecycle (`app/api/incidents.py`), playbook executor, evidence chain of custody (`app/models/evidence_custody.py`). |
| A.5.28 | Collection of evidence | Evidence attachment API (`app/api/evidence.py`) with SHA-256 hash verification. Legal hold mode (`app/models/evidence_legal_hold.py`). Chain-of-custody events immutably appended. |
| A.5.33 | Protection of records | Audit log (`app/models/audit.py`) — append-only events for all security-relevant actions. Settings changes write audit entries (`app/api/settings.py`). Detection rule changes are versioned in `DetectionRuleHistory` with full snapshot diffs, actor, and timestamp — immutable change record per rule version. |
| A.5.36 | Compliance with policies | PR template enforces SC-1 through SC-10 security checklist per feature (`.github/pull_request_template.md`). SECURITY-IMPACT.md (SC-1) provides per-feature security analysis. |

### A.6 — People Controls

| Control | Description | Implementation |
|---|---|---|
| A.6.8 | Information security event reporting | In-app notification system for critical alerts and SLA breaches. Source health cockpit (`GET /sources/health`) for SOC operations awareness — per-connector freshness, error budget, and stale-source detection. AI governance metrics (`GET /resilience/ai-governance/metrics`) surface hallucination rates for analyst awareness of AI output quality. |

### A.7 — Physical Controls

*(Out of scope — cloud-hosted platform; physical controls are the responsibility of the cloud provider.)*

### A.8 — Technological Controls

| Control | Description | Implementation |
|---|---|---|
| A.8.2 | Privileged access rights | Admin role (`users:manage` permission) required for user management. `admin:write` required for detection rule lifecycle operations (create, update, approve, rollback, delete) and resilience administration (secrets policies, tenant workspaces, DR drills). CODEOWNERS (`.github/CODEOWNERS`) restricts who can approve security-sensitive changes. |
| A.8.4 | Access to source code | CODEOWNERS enforces code-owner review for `app/security/`, `app/api/auth.py`, `app/models/user.py`, `.github/workflows/`. |
| A.8.9 | Configuration management | Settings change audit logging (`app/api/settings.py` — AuditLog entries per key changed with old/new values, sensitive keys redacted). Detection rule lifecycle versioning (`app/api/detection_rules.py` — `DetectionRuleHistory` snapshots with full diffs, peer approval, and rollback capability). Settings values are validated against `ALLOWED_KEYS` allowlist; unsafe characters (`\n\r\x00\`$;|&`) rejected. `.env` file permissions set to `0600` after every write. |
| A.8.15 | Logging | `AuditLog` model records actor, action, target, metadata, created_at for all security events. Detection rule changes additionally versioned in `DetectionRuleHistory`. IR runbook approval state transitions appended to `RunbookApprovalRequest.audit_trail`. Observability stack: correlation IDs, structured JSON logs. |
| A.8.16 | Monitoring activities | Source health monitor (`app/services/source_health.py`). Dashboard freshness indicator (`ingest_lag_minutes`). Queue ops panel showing stale assignments (`GET /alerts/queue/stats`). Source health cockpit (`GET /sources/health`) with per-connector freshness SLOs, error budget remaining, and consecutive failure counts. MITRE coverage by source quality (`GET /resilience/mitre/source-quality`) highlights telemetry blind spots. |
| A.8.19 | Installation of software | Dependency audit workflow (`.github/workflows/dependency-audit.yml`) — pip-audit, Safety, npm audit, Trivy on every PR. |
| A.8.24 | Use of cryptography | RSA JWT signing (`app/security/auth.py`). bcrypt password hashing. SHA-256 checksums on compliance report artifacts (`app/api/scheduled_reports.py`). Evidence hash verification (`app/api/evidence.py`). Detection rule SIGMA YAML parsed with `yaml.safe_load()` (safe deserialization — no arbitrary object instantiation). |
| A.8.25 | Secure development lifecycle | Branch protection (SECURITY-GATES.md), PR template (SC-1 to SC-10), SAST/DAST/SCA on every PR, CodeQL analysis. |
| A.8.26 | Application security requirements | All API endpoints have explicit RBAC, CSRF protection on mutations, rate limiting, input validation, security headers. |
| A.8.28 | Secure coding | Bandit + Semgrep SAST. Pydantic strict input validation. Parameterised SQLAlchemy queries (no raw SQL). No hardcoded credentials. |
| A.8.29 | Security testing in development | `tests/security/` — authentication boundary tests, rate limit tests, input validation tests, crypto tests, P6 authz boundary tests. |
| A.8.30 | Outsourced development | N/A (internal development). |

---

## PCI-DSS v4.0 — Applicable Requirements

*(Applicable if platform processes, stores, or transmits cardholder data. Currently scoped to log ingestion only; no CHD stored.)*

| Requirement | Description | Implementation |
|---|---|---|
| 6.2 | Bespoke and custom software developed securely | SAST (Bandit, Semgrep), DAST (OWASP ZAP), dependency SCA on every PR. PR security checklist (SC-1 to SC-10). SECURITY-IMPACT.md provides per-feature security analysis for P6 and Detection Rules / Resilience features. `yaml.safe_load()` used for SIGMA YAML deserialization in detection rules. |
| 6.3.1 | All security vulnerabilities are identified and addressed | Dependabot weekly scans, pip-audit CVE checks, fail-closed CI gates on critical/high findings. Detection rule peer-approval (`POST /detection-rules/{id}/approve-change`) prevents unreviewed logic changes reaching production. |
| 6.4.1 | Public-facing web apps are protected against attacks | Security headers middleware (CSP, HSTS, X-Content-Type-Options, X-Frame-Options). Rate limiting. OWASP ZAP baseline scan on PRs. Input value sanitisation on settings writes (`_UNSAFE_VALUE_PATTERN` blocks shell metacharacters). `ALLOWED_KEYS` allowlist on settings API. |
| 7.2 | Access control systems are configured to deny access by default | `require_permission()` — default deny, explicit grant required per endpoint. Detection rule mutations require `admin:write`. Resilience admin operations (secrets policies, tenant workspaces, DR drills) require `admin:write`. Assets enrichment requires `assets:write`. |
| 8.2 | Group accounts and shared authentication are prohibited | Every user has a unique account. API keys are per-analyst and tied to the issuing user. Runbook approvals record individual `requested_by` and `approved_by` identities; self-approval explicitly blocked. |
| 8.3 | User authentication is managed | JWT with RS256, configurable expiry. Session invalidation via `TokenBlocklist`. Failed-login tracking and lockout. |
| 10.2 | Audit logs are implemented to support detection | `AuditLog` table captures actor, action, target, IP, timestamp for all security events. Immutable append-only. Detection rule lifecycle events captured in `DetectionRuleHistory` (versioned, with full diffs). IR runbook approval and execution events appended to `RunbookApprovalRequest.audit_trail`. Settings mutations (key name, actor, timestamp) logged to `AuditLog`. |
| 10.3 | Audit logs are protected from destruction and unauthorised modifications | Audit log entries have no DELETE endpoint. Legal hold prevents evidence deletion. `DetectionRuleHistory` records are never deleted (rule deletion creates a `delete` history entry, preserving the trail). |
| 10.5 | Retain audit log history | `retention-days: 90` on security report artifacts in CI. Legal hold on evidence prevents premature deletion. Detection rule history and runbook approval audit trails are retained indefinitely in the database. |
| 11.3 | External and internal vulnerabilities are identified and addressed | Trivy container scanning, pip-audit, npm audit, CodeQL — all fail-closed on critical/high. Detection QA replay framework (`POST /resilience/detection-qa/replay`) validates rule precision/recall against historical telemetry before promotion. |
| 12.10 | Suspected and confirmed security incidents are responded to promptly | Incident management workflow, playbook SOAR, evidence collection, chain of custody. IR runbook approval gates (`app/api/resilience.py`) enforce dual-control for high-risk response actions. DR drills (`/dr/drills`) document tested restore procedures with RPO/RTO actuals. |

---

## Control Gaps and Backlog

The following controls have partial or planned implementation:

| Gap | Status | Backlog Item |
|---|---|---|
| Row-level tenancy / data boundary isolation | Partial — tenant workspace registry implemented; data-layer enforcement pending | P5-8 (Tenant and data boundary controls) |
| Secrets management rotation (Vault/KMS) | Partial — rotation policy registry (`/resilience/secrets/policies`) implemented; actual Vault/KMS integration pending | P5-7 (Secrets management and rotation) |
| Branch protection rules enabled in GitHub | Manual step required | SG-7, SN-1, SN-2 |
| Time-bounded security exception tracking | Documented | See SECURITY-GATES.md — Security Exceptions section |
| Dual-control approval for high-risk IR actions | Implemented — `RunbookApprovalRequest` with self-approval prevention; full admin-level second approval for highest-risk actions is a future hardening item | P5-9 |
| Peer approval on initial detection rule creation | Gap — peer approval enforced on updates only, not initial creates | Detection Rules API (future iteration) |
| Webhook recipient allowlist for report delivery | Gap — no allowlist enforced on scheduled report delivery destinations | P6-9 follow-up |
| `last_error_message` sanitisation in source health | Gap — connector error messages may include internal hostnames/IP addresses | P6-10 follow-up |
| MFA enforcement for admin role | Gap — no MFA requirement in current authentication flow | Security hardening backlog |
| Injection controls for live hunt execution backend | Deferred — required before activating live query execution backend | P6-7 follow-up |

---

## Evidence Collection

For audit evidence, the following artifacts are available:

- **CI pipeline results**: Security workflow runs in GitHub Actions (`.github/workflows/security.yml`, `dependency-audit.yml`, `codeql.yml`, `dast-api-security.yml`)
- **Compliance report exports**: `GET /compliance/reports/{id}/export` — signed PDF/CSV bundles with SHA-256 checksum
- **Audit log export**: `GET /audit` — queryable audit event stream
- **Report delivery receipts**: `GET /scheduled-reports/{id}/delivery-status` — delivery chain with checksums
- **Evidence chain of custody**: `GET /evidence/{id}/custody` — immutable custody event log
- **Detection rule change history**: `GET /detection-rules/{id}/history` — versioned change log with actor, diff, approval status, and timestamps
- **Detection rule diff**: `GET /detection-rules/{id}/diff?from_version=N&to_version=M` — field-level diff between any two approved versions
- **Runbook approval audit trail**: `GET /resilience/runbook-approvals` — approval request records with append-only `audit_trail` per request
- **DR drill results**: `GET /resilience/dr/drills` — drill records with actual RPO/RTO measurements and executor identity
- **Secrets rotation posture**: `GET /resilience/secrets/rotation-check` — overdue credential rotation report
- **Source health cockpit**: `GET /sources/health` — per-connector freshness and error budget evidence
- **Detection QA replays**: `GET /resilience/detection-qa/replays` — precision/recall gate results per rule per replay run
- **AI governance metrics**: `GET /resilience/ai-governance/metrics` — hallucination rate, average analyst rating, and guardrail status

---

*This document is reviewed and updated with each major release. Owner: Security Engineering.*
