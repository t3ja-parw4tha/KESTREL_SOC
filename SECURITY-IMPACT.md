# Security Impact Analysis

**Platform**: KESTREL SOC Platform
**Document version**: 1.0
**Date**: 2026-03-15
**Scope**: P6 Section Hardening features and S1-S6 Security-First Delivery Mandate
**Author**: Security Engineering

This document satisfies checklist item **SC-1 (Scope & Risk)** for the P6 + Security hardening PR.
Each feature is analysed across six dimensions: authn/authz impact, data flow, trust boundaries,
abuse cases, mitigations, and residual risk.

---

## General Controls (apply to all features unless noted)

All endpoints described in this document share the following baseline controls:

- **Authentication**: Bearer JWT (RS256) required on every route. Tokens validated by `app/security/rbac.py:require_permission()`.
- **CSRF protection**: All state-mutating endpoints (`POST`, `PATCH`, `PUT`, `DELETE`) require a valid CSRF double-submit token via `app/security/csrf.py:verify_csrf`.
- **Input validation**: Pydantic v2 model validation on all request bodies; query parameters are typed and bounded.
- **Audit logging**: `AuditLog` entries (actor, action, target, metadata, timestamp) written for all security-relevant mutations.
- **Rate limiting**: Per-IP rate limiting applied by `app/security/rate_limit.py` globally.
- **Security headers**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options applied by `app/security/middleware.py`.
- **Parameterised queries**: All DB access uses SQLAlchemy ORM; no raw SQL string interpolation.

---

## P6-1 / P6-2: Dashboard Production Mode and Freshness Telemetry

**Endpoints**: `GET /dashboard/stats`, `GET /dashboard/section-quality-metrics`, `GET /dashboard/workflow-traceability`

**Authn/Authz impact**: Requires `dashboard:read` permission. All three roles (`viewer`, `analyst`, `admin`) hold this permission. No write path exists. No privilege escalation is possible through read-only KPI endpoints.

**Data flow**: Aggregated statistics only — counts, percentages, timestamps. No raw alert content, PII (IP addresses, usernames), or enrichment data is returned in these endpoints. The `last_ingest_at` field returns an ISO timestamp, not an event payload. Data stays within the trust boundary of the authenticated session and is not transmitted to external systems.

**Trust boundaries**: Inputs are limited to the `trend_period` query parameter (enum-validated: `day|week|month`). All data sourced from internal DB aggregation queries. No external API calls. The `ingest_lag_minutes` value is derived from the most recent `Alert.created_at` timestamp — an attacker controlling ingest timing could manipulate this metric, but cannot use the endpoint to exfiltrate data.

**Abuse cases**:
- An authenticated low-privilege `viewer` could poll the endpoint at high frequency to map alert volume patterns or infer organisational incident load. Blast radius: information disclosure of trend metadata only.
- The `trend_period` parameter does not paginate or expose raw records, so enumeration attack surface is minimal.

**Mitigations**: RBAC on `dashboard:read`. Rate limiting at the IP/session layer. No raw data returned. No demo fallback path; production mode returns 503 on DB failure rather than synthetic data.

**Residual risk**: **Low**. Read-only aggregate endpoint. The only remaining exposure is trend-pattern inference by a legitimate authenticated user, which is acceptable for a dashboard.

---

## P6-3: Alerts Queue Operations Panel

**Endpoints**: `GET /alerts/queue/stats`, `GET /alerts` (list), `PATCH /alerts/{id}`, `PATCH /alerts/bulk`, `POST /alerts/{id}/pick-up`

**Authn/Authz impact**:
- `GET /alerts/queue/stats`: `alerts:read` — available to `viewer`, `analyst`, `admin`.
- `PATCH /alerts/{id}` (status/assignment): `alerts:update_status`.
- `POST /alerts/{id}/pick-up`: `alerts:pick_up`.
- `PATCH /alerts/bulk` assignment to another user: additionally requires `alerts:assign` and a non-empty `assign_comment`.
- Reassigning another analyst's alert requires `alerts:assign`; self-assignment and self-drop require only `alerts:pick_up`.

**Data flow**: The queue stats endpoint returns analyst usernames (from `assigned_to` field) and alert counts. Analyst usernames are internal identifiers and are not considered PII under the platform's data classification. Alert IDs, status values, and assignment targets transit on state-mutation endpoints. Raw alert content (source IP, destination IP, MITRE techniques) is not returned by queue stats.

**Trust boundaries**: `assigned_to` values are user-supplied strings (max 256 chars). These are stored as-is without resolving against a user directory, meaning an analyst with `alerts:assign` permission could assign an alert to an arbitrary string value that does not correspond to a real user account. This is a known limitation: assignment validation against the user table is not enforced at the API layer.

**Abuse cases**:
- Bulk update endpoint (`PATCH /alerts/bulk`) accepts up to 200 alert IDs. A malicious analyst with `alerts:bulk_update` could mass-resolve or mass-reassign alerts to disrupt triage. Blast radius: SOC operational disruption; no data exfiltration path.
- An analyst could pick up alerts they are not qualified to handle (no skill-based routing enforcement exists).
- The assignment comment required for reassignment provides an audit trail deterrent but cannot prevent motivated abuse by a legitimate `analyst` or `admin` role user.

**Mitigations**: ID pattern validation (`^[a-zA-Z0-9\-]{1,36}$`) and 200-record cap on bulk operations. Deduplication check prevents duplicate IDs in a bulk request. CSRF protection on all mutations. AuditLog records every mutation with actor, alert IDs, old/new status, and assignment details. Reassignment to another user requires `assign_comment` for team visibility.

**Residual risk**: **Low**. Bulk disruption by a compromised `analyst` account is possible but limited to workflow interference with no data loss path.

---

## P6-4: Incidents API-Only Reliability

**Endpoints**: `GET /incidents`, `GET /incidents/{id}`, `POST /incidents`, `GET /incidents/{id}/actions`, `PUT /incidents/{id}/actions`

**Authn/Authz impact**:
- Read: `incidents:read` (viewer, analyst, admin).
- Write (`POST /incidents`, `PUT /{id}/actions`): `incidents:write` (analyst, admin).
- No admin-only path. Any analyst can create incidents and save response actions.

**Data flow**: Incident data is entirely derived from correlated `Alert` records. No new PII is introduced by the incidents layer. The `PUT /{id}/actions` endpoint persists free-form action items (label, assignee, completion state) inside the anchor alert's `enrichment` JSONB column. An `assignee` field in `ResponseActionItem` is unconstrained text (no user-lookup validation), which could be used to store arbitrary strings.

**Trust boundaries**: `title_override` (max 256 chars) is user-supplied and validated by Pydantic. Alert IDs supplied in `POST /incidents` are validated by DB lookup — unknown IDs are silently skipped (logged in response). Actions payload in `PUT /{id}/actions` replaces (not merges) existing actions; there is no incremental append path.

**Abuse cases**:
- An analyst could create a large number of incidents from overlapping alert sets, polluting the incident view. Conflicts are rejected (alerts already grouped return 409), which limits the blast radius.
- `PUT /{id}/actions` performs a full replace, so a racing concurrent write could lose another analyst's action updates. No optimistic locking is implemented.
- An analyst could assign actions to arbitrary `assignee` strings.

**Mitigations**: CSRF on all mutations. RBAC on `incidents:write`. `alert_ids` validated against DB; 409 on already-grouped alerts. Pydantic field limits on `title_override`. No demo fallback path; 404 returned when no alerts match the incident ID.

**Residual risk**: **Low-Medium**. The lack of optimistic locking on action saves is a data integrity risk under concurrent access. Accepted for initial delivery; tracked for future improvement.

---

## P6-5: Assets Enrichment (POST /assets/{id}/enrich)

**Endpoints**: `POST /assets/{id}/enrich`

**Authn/Authz impact**: Requires `assets:write` (analyst, admin). The enrichment computation is read-only from the DB perspective (reads alert telemetry) and writes only `confidence_score` and `last_enriched_at` back to the asset record. No escalation path through this endpoint.

**Data flow**: Reads `Alert.risk_score`, `Alert.asset_id`, and `Alert.status` from the DB. No external API calls are made; confidence computation is entirely local. The `confidence_score` written (0.0–1.0) is derived from open alert counts and max risk score. No PII flows out of this endpoint.

**Trust boundaries**: The `asset_id` path parameter is matched against the DB; 404 returned for unknown IDs. No external trust dependencies. The confidence algorithm is deterministic and based solely on internal telemetry; it cannot be influenced by user-supplied parameters beyond triggering the recalculation.

**Abuse cases**:
- A malicious analyst could trigger enrichment on all assets at high frequency to degrade DB performance (denial of service against the enrichment pipeline). The endpoint performs two DB queries per call; rate limiting at the IP layer is the primary protection.
- Confidence scores are intentionally approximate (not cryptographically signed), so a `confidence_score` value could mislead analysts into trusting an asset's posture. This is a design-level trust assumption, not an injection risk.

**Mitigations**: CSRF. RBAC on `assets:write`. `asset_id` validated by DB lookup. Confidence calculation is bounded (0.0–1.0). Rate limiting at API gateway.

**Residual risk**: **Low**. The DoS risk from bulk enrichment triggers is mitigated by rate limiting. The approximate confidence metric is a known design trade-off.

---

## P6-6: MITRE Live Coverage Engine (GET /mitre/coverage)

**Endpoints**: `GET /dashboard/stats` (includes `coverage_pct`, `techniques_detected`), `GET /resilience/mitre/source-quality`

**Authn/Authz impact**: `dashboard:read` (all roles) for coverage stats. `sources:read` (all roles) for source quality. Read-only; no mutations.

**Data flow**: Aggregates `Alert.mitre_techniques` JSONB column across all alerts. Technique IDs (e.g., `T1078`) and tactic names are matched against the static `TECHNIQUES` dictionary (`app/core/mitre/techniques.py`). Source names and alert counts are returned in `source-quality`. No PII, no raw alert content returned.

**Trust boundaries**: The static `TECHNIQUES` dictionary is the trusted ATT&CK reference. Alert `mitre_techniques` values ingested from external SIEMs are untrusted input; the engine only extracts `technique_id` strings and `tactic` names, discarding all other fields from the JSONB. Malformed JSONB values are handled defensively (`isinstance` guards in extraction loops).

**Abuse cases**:
- An attacker who can inject alerts with crafted `mitre_techniques` payloads could artificially inflate coverage metrics, misleading management reporting. Blast radius: metric manipulation; no code execution path.
- Source names (`Alert.source`) are used as dict keys in the quality aggregation; an oversized source name could degrade performance but not cause injection.

**Mitigations**: `isinstance` guards on all JSONB field extraction. Techniques are matched by ID string only; no eval or dynamic dispatch. Read-only endpoints with RBAC. Ingest pipeline validates the `mitre_techniques` schema on alert creation.

**Residual risk**: **Low**. Coverage metric manipulation via crafted ingest is a trust question for the ingest pipeline, not this endpoint.

---

## P6-7: Threat Hunting Execution (GET/POST/DELETE /hunting/queries)

**Endpoints**: `GET /hunting/queries`, `POST /hunting/queries`, `DELETE /hunting/queries/{id}`, and associated run/results endpoints.

**Authn/Authz impact**: Hunt query CRUD requires `threats:hunt` permission (analyst, admin). Read access to saved hunts is available to all authenticated users with `alerts:read`. Delete requires ownership or admin role (implementation detail varies by endpoint; verify `created_by` check in hunt query model).

**Data flow**: Hunt queries store a query string and metadata server-side in `HuntQueryRecord`. Hunt results (`HuntResultRecord`) store matching alert IDs and analyst annotations. PII may be present indirectly if query strings reference IP addresses or usernames. Results are linked back to `Alert` records via `alert_id` FK. No outbound transmission to external systems from the results path.

**Trust boundaries**: Query strings are user-supplied. The platform's hunt execution is simulated (results are derived from existing alerts, not fed to a live query engine in P6). In a production deployment with a live query backend, the query string would constitute a high-trust input requiring SQL/SPL/KQL injection prevention at the query translation layer.

**Abuse cases**:
- An analyst could save hunts with misleading names to confuse colleagues (social engineering within the team). Low blast radius.
- If a live query execution backend is connected in future, unsanitised query strings could enable injection attacks (SPL injection, KQL injection). This risk is deferred pending backend integration.
- Saved hunts accumulate indefinitely; no retention/quota enforcement exists (potential storage growth).

**Mitigations**: CSRF on mutations. RBAC on `threats:hunt`. Query strings are stored as text and not executed against a live query engine in the current implementation. Results are linked by alert ID (UUID format).

**Residual risk**: **Medium** — if a live hunt execution backend is integrated without adding query validation/sanitisation, injection risk escalates to High. Accepted pending future backend integration with explicit injection controls required before activation.

---

## P6-8: Playbook Dry-Run (POST /playbooks/{id}/dry-run)

**Endpoints**: `POST /playbooks/{id}/dry-run`

**Authn/Authz impact**: Requires `playbooks:run` (analyst, admin). The dry-run endpoint is read-only with respect to infrastructure — it inspects playbook action definitions and classifies risk levels without executing any actions. No escalation path.

**Data flow**: Reads `Playbook.actions` JSONB column. Returns action types, risk classifications, and descriptions derived from action metadata. No external API calls made. No PII returned. The `requires_approval` flag in the response informs the caller if any action is classified as `high` risk (isolate_host, disable_user, quarantine).

**Trust boundaries**: `playbook_id` is an integer validated by DB lookup. The `_action_risk_level()` function maps action type strings to risk levels using an allowlist; unknown action types default to `medium` risk. The action `value` field from stored JSONB is returned in the description string — this value is sourced from the playbook definition created by an admin and is not user-supplied per dry-run request.

**Abuse cases**:
- An analyst could use dry-run to enumerate all actions in a playbook, including sensitive targets (e.g., the value of a `block_ip` action). If playbooks contain sensitive network targets as literal values in their action definitions, this constitutes information disclosure to any `playbooks:run` holder.
- A high-volume of dry-run calls does not trigger execution, so there is no operational impact from repeated calls.

**Mitigations**: CSRF. RBAC on `playbooks:run`. No action is executed. Risk classification uses an explicit allowlist. Audit logging is not currently added for dry-run calls (read-only, no state change). Future improvement: add audit log for dry-run access to high-risk playbooks.

**Residual risk**: **Low**. The information disclosure of action values is accepted given that playbook definitions are already visible to all authenticated users via `GET /playbooks`.

---

## P6-9: Scheduled Reports Trust Chain (POST /scheduled-reports, delivery receipts, checksums)

**Endpoints**: `POST /scheduled-reports`, `GET /scheduled-reports/{id}/delivery-status`, `POST /compliance/reports/{id}/export`

**Authn/Authz impact**: Report creation and export require `admin:write`. Delivery status read requires at minimum `reports:read`. No viewer-accessible mutation paths.

**Data flow**: Report artifacts contain aggregated compliance evidence (alert counts, case summaries, SLA metrics). Artifacts are SHA-256 checksummed at generation time (`app/api/scheduled_reports.py`). Reports are stored server-side and optionally delivered via email/webhook. Delivery receipts include checksum, delivery timestamp, and recipient. PII may be present in compliance evidence if alert content includes user identifiers; redaction policy is the responsibility of the report template, not the delivery chain.

**Trust boundaries**: Report recipient email addresses and webhook URLs are configured by admins and stored in `ScheduledReport` records. These represent outbound trust boundaries — the platform sends data to configured external destinations. Webhook URLs and email addresses must be validated and allowlisted to prevent Server-Side Request Forgery (SSRF) or data exfiltration to attacker-controlled endpoints. Current implementation does not enforce a recipient allowlist (noted as residual risk).

**Abuse cases**:
- An admin with access to report configuration could add a malicious webhook URL to receive compliance report payloads. SSRF risk if the webhook delivery mechanism follows redirects.
- Report artifacts stored server-side could be accessed by any admin; no per-report access control beyond admin RBAC.
- A large `replay_window_days` parameter on detection QA replays (up to 365) could trigger a computationally expensive DB scan. The 500-record limit in `run_detection_replay` mitigates worst-case DB load.

**Mitigations**: SHA-256 artifact checksums for tamper detection. Delivery receipts are immutable (append-only). Admin-only RBAC on creation. CSRF on all mutations. Report IDs are UUIDs (not guessable). Retention policy (`retention-days: 90`) on CI artifacts.

**Residual risk**: **Medium**. The absence of a recipient allowlist for webhook delivery is an accepted residual risk. Recommended follow-up: validate webhook URLs against an allowlist and block internal/private IP ranges before delivery.

---

## P6-10: Source Health Cockpit (GET /sources/health)

**Endpoints**: `GET /sources/health`, `GET /sources`

**Authn/Authz impact**: Requires `sources:read` (all authenticated roles including viewer). Read-only. No mutation path on these endpoints.

**Data flow**: Returns source health metrics: freshness seconds, ingest lag, error budget percentage, success/failure window counts, last error message. The `last_error_message` field may contain connector error text that includes partial credential information or internal hostnames in edge cases (e.g., "Connection refused to 10.0.0.5:8089"). This constitutes potential internal network topology disclosure.

**Trust boundaries**: `SourceHealth` records are populated by the background connector runner (`app/connectors/runner.py`). The health data itself is internal; no external API calls are made from the `/sources/health` endpoint. Source configuration (including secret credential keys) is not returned by health endpoints — only health metrics.

**Abuse cases**:
- A viewer-role user could enumerate source health metrics to identify stale/failed connectors, which could be useful for timing attacks against detection gaps (attack while the EDR connector is stale).
- `last_error_message` could leak internal hostnames, IP addresses, or error text from failed connector authentication attempts.

**Mitigations**: RBAC enforced. Source credentials are not returned. Read-only endpoint. Error messages are stored by the connector runner; scrubbing sensitive content from error messages is a recommended improvement.

**Residual risk**: **Low-Medium**. The `last_error_message` disclosure is a known information leakage risk. Accepted pending a sanitisation pass on connector error handling.

---

## P6-11: Context-Aware Help

**Endpoints**: No dedicated API endpoints. Implemented as frontend-only contextual guidance (`frontend/src/pages/Help.tsx`).

**Authn/Authz impact**: Help content is rendered client-side after authentication. No server-side permission check required beyond general session authentication. All roles can access all help content (no role-differentiated runbooks at the API level in this iteration).

**Data flow**: No sensitive data flows through help functionality. Help content is static text and links embedded in the frontend bundle. No user data is sent to external help systems.

**Trust boundaries**: Help content is fully controlled by the platform deployment. No external content loading (no iframes to external help portals). No analytics or telemetry sent to third parties for help usage tracking.

**Abuse cases**: Minimal. An attacker with access to the frontend bundle could read help content, but this provides no operational advantage beyond what is available through normal use.

**Mitigations**: Authentication required to access the application. Content is static and bundled; no runtime content fetching from external sources. CSP headers block external script/frame sources.

**Residual risk**: **Low**. No meaningful attack surface in static help content.

---

## P6-12: User Activity Audit (GET /auth/users/{id}/activity)

**Endpoints**: `GET /auth/users/{id}/activity`, `GET /auth/users`, `PATCH /auth/users/{id}`

**Authn/Authz impact**: Activity stream requires `users:manage` (admin only). User listing and management also require `users:manage`. Analysts and viewers cannot access other users' activity data. Admins can view any user's activity log.

**Data flow**: Returns `AuditLog` entries filtered by analyst/user ID: action types, timestamps, target IDs, metadata blobs. AuditLog `details` fields may contain partial alert content (e.g., the text of a comment added to an alert). No password hashes or credential data are returned. User objects include `username`, `email`, `role`, `is_active`, `failed_login_count` — PII is present.

**Trust boundaries**: User IDs in path parameters are integer primary keys. DB lookup returns 404 for unknown IDs (no enumeration of valid IDs via error differentiation for non-admin callers, since the RBAC check fires first). The admin role is fully trusted to access all user activity; no user can access their own activity without admin role (i.e., self-inspection is not supported at a lower privilege level).

**Abuse cases**:
- A compromised admin account is the primary risk: full access to all user activity, email addresses, and role assignments. This is the intended admin capability but represents maximum blast radius if an admin account is compromised.
- Bulk export of user activity via repeated pagination is possible. No rate limit specifically on the activity endpoint beyond global rate limits.

**Mitigations**: Admin-only RBAC. Audit log is append-only (no DELETE on AuditLog). Failed login counts visible to admin for anomaly detection. JWT session management with `TokenBlocklist` for revocation of compromised admin tokens.

**Residual risk**: **Medium**. Depends on the security of admin accounts. Recommend MFA enforcement for admin role as a follow-up control (not yet implemented).

---

## P6-13: Settings Governance Audit

**Endpoints**: `GET /settings`, `POST /settings`, `DELETE /settings/{key}`

**Authn/Authz impact**: All settings endpoints require `admin:write`. No non-admin access path. Settings contain API keys for all connected systems (AI providers, EDR platforms, cloud providers) — this is the highest-sensitivity configuration surface in the platform.

**Data flow**: Sensitive keys (AI provider keys, connector secrets) are stored in the `.env` file on the server filesystem. The `GET /settings` response redacts all sensitive values (`[REDACTED]`). The `POST /settings` endpoint writes values to `.env` and logs the key name (not value) to `AuditLog` with `old_value` (redacted) and `new_value` (redacted for sensitive keys). File permissions are set to owner-read-write-only (`0600`) after each write.

**Trust boundaries**: The `.env` file is an internal trust boundary. The settings API provides an admin-authenticated interface to modify it. Input values are sanitised against an unsafe-character pattern (`[\n\r\x00\`$;|&]`) before writing to prevent file injection attacks. Only keys in the `ALLOWED_KEYS` allowlist can be written.

**Abuse cases**:
- A compromised admin account could overwrite all connector API keys, breaking ingestion from all sources. This is a Denial-of-Service against the detection pipeline.
- An admin could inject a malicious `SLACK_WEBHOOK_URL` or `ALERT_EMAIL` to redirect notifications to an attacker-controlled endpoint (data exfiltration of alert summaries).
- If the unsafe-character sanitisation is bypassed, a carefully crafted value could corrupt the `.env` file syntax, causing application startup failure.
- The `DELETE /settings/{key}` endpoint removes a setting by key; repeated deletes could degrade platform functionality.

**Mitigations**: Admin-only RBAC. CSRF on all mutations. `ALLOWED_KEYS` allowlist prevents arbitrary key writes. `_UNSAFE_VALUE_PATTERN` regex blocks shell metacharacters. Sensitive values redacted in audit log and API responses. File permissions locked to `0600`. All changes produce AuditLog entries with actor, key, and timestamp.

**Residual risk**: **High** (inherent to the design). The `.env` file contains production secrets. Full mitigation requires migration to a proper secrets manager (Vault/KMS — tracked as P5-7). Until then, the compensating controls (admin-only RBAC, audit logging, input sanitisation, file permission hardening) reduce but do not eliminate the risk. **Accepted by security owner for initial delivery pending P5-7 completion.**

---

## Detection Rules API (POST/PATCH/DELETE /detection-rules, approve-change, rollback, test)

**Endpoints**: `POST /detection-rules`, `PATCH /detection-rules/{id}`, `DELETE /detection-rules/{id}`, `POST /detection-rules/{id}/approve-change`, `POST /detection-rules/{id}/rollback`, `POST /detection-rules/{id}/test`, `GET /detection-rules/{id}/history`, `GET /detection-rules/{id}/diff`

**Authn/Authz impact**:
- Create, update (change request), delete, approve, rollback: `admin:write` only.
- Read (list, history, diff): `alerts:read` (all roles including viewer).
- Test a rule against an event: `alerts:read` (analyst/viewer can test rules without triggering them).
- Peer-approval enforcement: the `approve-change` endpoint explicitly rejects self-approval (`requester cannot self-approve` — 409). This enforces four-eyes / dual-control on rule changes.

**Data flow**: Rule definitions include `sigma_yaml` (SIGMA detection logic) and `conditions` (custom rule JSON). These are stored in `DetectionRule` and versioned in `DetectionRuleHistory` with full snapshot diffs. Rule test events (`POST /{id}/test`) accept arbitrary JSON event objects — this is the primary untrusted input surface.

**Trust boundaries**:
- `sigma_yaml` is parsed with `yaml.safe_load()` (not `yaml.load()`), preventing YAML deserialization attacks.
- Custom rule `conditions` are evaluated by `evaluate_custom_rule()` in `app/core/detection_rules/engine.py` against user-submitted test events. The engine must not execute arbitrary code or allow template injection; this should be verified during security testing.
- Rule names are validated for uniqueness at both change-request and approval time.

**Abuse cases**:
- An admin could create a rule that matches no alerts (dead rule) or one that matches all alerts (denial-of-service through alert flood). No rate limit on alerts generated by rules.
- An admin could roll back a rule to a known-weak version to blind detections during an attack window. Rollback is logged to history, providing forensic trail but no prevention.
- The `test` endpoint accepts arbitrary JSON events up to the default FastAPI body size limit. A very large event document could cause memory pressure during evaluation.
- Without four-eyes enforcement on the initial `POST /detection-rules` (create), a single admin can introduce a new rule without peer review. The peer-approval gate applies only to subsequent updates.

**Mitigations**: `yaml.safe_load()` for SIGMA parsing. Peer-approval enforced on updates (not creation). Full version history with diffs. Rollback creates a new history entry (not silent revert). CSRF on all mutations. `admin:write` required for all mutations. `name` field length-bounded (max 160 chars). `description` max 1024 chars. `reason` max 512 chars.

**Residual risk**: **Medium**. The lack of peer approval on initial rule creation is a known gap. Existing rules require peer approval for all subsequent changes, limiting the window for unilateral modification. Accepted pending enforcement of creation peer-review in a future iteration.

---

## Resilience API (detection-qa, secrets, tenants, runbook-approvals, dr/drills, ai-governance)

### Detection QA (`POST /resilience/detection-qa/replay`)

**Authn/Authz impact**: `admin:write` required. Read-only against alert DB; writes QA run records.

**Data flow**: Reads up to 500 alerts from the specified replay window. Returns precision/recall metrics and a gate result. No raw alert content returned in the response — only aggregated stats. QA run records are stored with `created_by` (user ID).

**Trust boundaries**: `replay_window_days` bounded (1–365). `dataset_name` bounded (2–128 chars). `min_precision_pct` and `min_recall_pct` bounded (0–100). The simulated match logic is deterministic and based on alert category/severity — no user-controlled rule evaluation occurs in the replay path.

**Abuse cases**: A 365-day replay window with large alert volumes could trigger a slow DB scan (500-record limit mitigates worst case). Repeated replay runs inflate the `DetectionQARun` table.

**Mitigations**: CSRF. RBAC. 500-record alert query limit. Input bounds on all parameters.

**Residual risk**: **Low**.

---

### Secrets Rotation Policies (`GET/POST /resilience/secrets/policies`, `GET /resilience/secrets/rotation-check`)

**Authn/Authz impact**: `admin:write` required for all secrets policy endpoints. No viewer/analyst path.

**Data flow**: Stores and retrieves `SecretRotationPolicy` records: `secret_name`, `provider`, `rotation_days`, `owner`, `last_rotated_at`. Critically: **actual secret values are never stored or returned by this API**. This is a policy/metadata registry, not a secrets vault. The `secret_name` field is a label (e.g., `OPENAI_API_KEY`) used for tracking purposes only.

**Trust boundaries**: `secret_name` max 128 chars. `provider` max 32 chars. `rotation_days` bounded (1–3650). The rotation check computes overdue status based on `last_rotated_at` — this value is user-supplied and could be set to a future date to make an overdue secret appear compliant.

**Abuse cases**: An admin could set `last_rotated_at` to a future date to suppress overdue warnings, masking a compliance violation. Blast radius: audit/compliance data integrity, not security control bypass.

**Mitigations**: CSRF. RBAC. Pydantic validation on all inputs. Rotation check results are advisory — they do not gate access to actual secrets.

**Residual risk**: **Low-Medium**. `last_rotated_at` manipulation is a compliance integrity risk. Recommend read-only sourcing from the actual secrets provider (Vault/KMS) in the P5-7 implementation.

---

### Tenant Workspaces (`GET/POST /resilience/tenants/workspaces`, `GET /resilience/tenants/isolation-check`)

**Authn/Authz impact**: `admin:write` required. Read-only isolation check also requires `admin:write`.

**Data flow**: Stores `org_id`, `workspace_id`, `description`, `is_active`. These are configuration identifiers, not data-bearing records. The isolation check verifies uniqueness of org/workspace pairs.

**Trust boundaries**: `org_id` max 64 chars, `workspace_id` max 64 chars. No row-level tenant isolation is enforced by the data layer in the current implementation; tenant workspace records are administrative metadata only (P5-8 gap noted in SECURITY-CONTROLS.md).

**Abuse cases**: An admin could create duplicate workspace entries that confuse the isolation check (409 prevents exact duplicates, but similar names could mislead operators).

**Mitigations**: CSRF. RBAC. 409 on exact duplicate pairs. Pydantic field limits.

**Residual risk**: **Low**. Tenant isolation at the data layer remains a planned control (P5-8).

---

### IR Runbook Approvals (`GET/POST /resilience/runbook-approvals`)

**Authn/Authz impact**: Read and approve require `playbooks:run` (analyst, admin). Execute requires `playbooks:run`. Dual-control: requester cannot self-approve (enforced via 409).

**Data flow**: Approval records include `playbook_id`, `alert_id`, `risk_level`, `requested_by`, `approved_by`, `executed_by`, `audit_trail` (append-only JSON array), timestamps. The `action_summary` field contains a description of what the playbook would do. No secrets or credentials in the approval record.

**Trust boundaries**: The approval flow trusts that `requested_by` and `approved_by` are different users (enforced by comparing `user.get("sub")` values). The `execute` endpoint trusts that `status == "approved"` is an unforgeable pre-condition, enforced by the DB state machine.

**Abuse cases**:
- Two colluding analysts (A approves B's request, B approves A's request) can bypass the intent of dual-control. Standard insider threat risk, not preventable by the API alone.
- The execute endpoint calls `execute_playbook_actions()` which performs real SOAR actions (isolate host, block IP, disable user). A compromised `playbooks:run` account that navigates the approval chain has high blast radius.

**Mitigations**: Self-approval prevention (409). Append-only audit trail in `RunbookApprovalRequest.audit_trail`. CSRF. RBAC. Execution gated on `status == "approved"`. All state transitions logged.

**Residual risk**: **Medium**. Collusion between two `playbooks:run` holders can execute high-risk actions. Mitigated by audit trail and manual review capability. Full mitigation would require admin-level approval for high-risk actions — tracked as a future improvement.

---

### DR Drills (`GET/POST /resilience/dr/drills`, `POST /resilience/dr/drills/{id}/run`)

**Authn/Authz impact**: `admin:write` required for all DR drill operations.

**Data flow**: Drill records store `target` (system name, max 128 chars), RPO/RTO targets and actuals, status, and execution metadata. The `target` field is a label (e.g., "alertdb", "postgres") — not an executable command. Drill execution is simulated (deterministic formula based on drill ID) and does not make external system calls.

**Trust boundaries**: All inputs are Pydantic-validated. The `target` field is stored as text and displayed in the UI — no command execution or template rendering occurs on this value.

**Abuse cases**: Minimal. Drill records are administrative records with no execution impact. An admin could create and run drills with fabricated pass results to mislead DR posture metrics.

**Mitigations**: CSRF. RBAC. Pydantic field bounds. Simulated execution prevents real infrastructure impact from drill runs.

**Residual risk**: **Low**.

---

### AI Governance (`POST /resilience/ai-governance/feedback`, `GET /resilience/ai-governance/metrics`)

**Authn/Authz impact**: Feedback submission requires `alerts:write` (analyst, admin). Metrics read requires `alerts:read` (all roles).

**Data flow**: Feedback records store `alert_id`, `analyst` (user ID), `rating` (1–5), `hallucination_flag`, `confidence_score`, and free-text `comments` (max 2000 chars). The `comments` field is user-supplied free text — potential storage of PII (analyst opinions about specific incidents, names of individuals mentioned in alerts).

**Trust boundaries**: `alert_id` max 64 chars. `rating` bounded (1–5). `confidence_score` bounded (0–1). `comments` max 2000 chars. The `alert_id` is not validated against the Alert table (no FK check in the API layer) — an analyst could submit feedback referencing a non-existent alert ID.

**Abuse cases**:
- An analyst could flood the feedback table with synthetic entries to corrupt the hallucination rate and average rating metrics, causing false `guardrail_status: healthy` readings that mask real AI quality degradation.
- Free-text `comments` could contain sensitive operational information that is stored without additional access controls.

**Mitigations**: CSRF. RBAC. Pydantic field bounds. Metrics are advisory (not gating). `guardrail_status: degraded` threshold at >20% hallucination rate.

**Residual risk**: **Low-Medium**. Metric manipulation by a malicious insider is possible. Recommend adding input sanity checks (minimum feedback volume threshold before trusting `guardrail_status` transitions) in a future iteration.

---

## S1–S6: Security-First Delivery Mandate Controls

The following addresses the security mandate items as platform-wide controls rather than per-feature:

### S1 — Secure Coding Patterns by Default

All new features implement: `require_permission()` RBAC on every endpoint, CSRF on all mutations, Pydantic request validation, SQLAlchemy ORM (no raw SQL), `yaml.safe_load()` for YAML parsing, and bounded field lengths throughout. Sensitive values (API keys, tokens) are never returned in API responses.

**Residual risk**: **Low**.

### S2 — Framework Compliance Before Release

New features maintain existing SOC 2 CC6/CC7, ISO 27001 A.8, and PCI-DSS 10.x controls. Control mapping updates are documented in SECURITY-CONTROLS.md (SC-2). Detection Rules peer-approval satisfies CC7 (Change Management). Audit trail on all mutations satisfies PCI-DSS 10.2.

**Residual risk**: **Low**.

### S3 — No Quick-Hack Implementations

No temporary security bypasses were introduced. Where a control gap exists (e.g., P5-7 secrets management, P5-8 tenant isolation), the gap is documented with explicit backlog references rather than bypassed.

**Residual risk**: **Low**.

### S4 — Feature PRs Include Security Impact Analysis

This document satisfies S4 for the P6 + Security PR. Future feature PRs must reference SECURITY-IMPACT.md or provide equivalent per-PR security analysis per the PR template (`.github/pull_request_template.md` SC-1 checkbox).

**Residual risk**: **Low**.

### S5 — Security Tests Required

The test suite includes: `tests/test_p6_features.py` (authz boundary tests, CSRF rejection tests), `tests/test_p5_features.py` (detection QA, runbook approval dual-control, DR drill), `tests/test_assets_api.py`, `tests/test_cases_api.py`, `tests/test_evidence_ai_assistant.py`, `tests/test_watchlist_matching.py`. Security workflow gates (Bandit, Semgrep, pip-audit, Safety, Trivy, TruffleHog, CodeQL) run on every PR.

**Residual risk**: **Low-Medium**. Injection/fuzz test coverage for the detection rules `test` endpoint and hunt query strings should be expanded.

### S6 — Release Gates Fail Closed

CI security gates in `.github/workflows/security.yml` and `dependency-audit.yml` are configured to fail the PR on critical/high findings. CodeQL (`.github/workflows/codeql.yml`) and DAST (`.github/workflows/dast-api-security.yml`) gates are required checks. Branch protection (SG-7) is a pending manual step required before full fail-closed operation.

**Residual risk**: **Medium** until SG-7 (branch protection rules) and SN-1/SN-2 (required checks + CODEOWNERS enforcement) are activated in GitHub settings.

---

## Summary Risk Register

| Feature | Residual Risk | Key Open Item |
|---|---|---|
| P6-1/P6-2 Dashboard Freshness | Low | None |
| P6-3 Alerts Queue Ops | Low | Assignment validation against user table |
| P6-4 Incidents API-Only | Low-Medium | Optimistic locking on action saves |
| P6-5 Assets Enrichment | Low | None |
| P6-6 MITRE Live Coverage | Low | None |
| P6-7 Threat Hunting | Medium | Injection controls required before live query backend integration |
| P6-8 Playbook Dry-Run | Low | None |
| P6-9 Reporting Trust Chain | Medium | Webhook recipient allowlist |
| P6-10 Source Health Cockpit | Low-Medium | `last_error_message` sanitisation |
| P6-11 Context-Aware Help | Low | None |
| P6-12 User Activity Audit | Medium | MFA enforcement for admin role |
| P6-13 Settings Governance | High (inherent) | P5-7 secrets manager migration (tracked) |
| Detection Rules API | Medium | Peer approval on initial rule creation |
| Resilience — Detection QA | Low | None |
| Resilience — Secrets Policies | Low-Medium | Rotation date sourced from Vault/KMS (P5-7) |
| Resilience — Tenants | Low | P5-8 data-layer tenant isolation |
| Resilience — Runbook Approvals | Medium | Admin-level approval for high-risk actions |
| Resilience — DR Drills | Low | None |
| Resilience — AI Governance | Low-Medium | Metric manipulation threshold checks |
| S1-S6 Security Mandate | Low-Medium | SG-7 branch protection, SN-1/SN-2 required checks |

*This document is reviewed and updated with each major release. Owner: Security Engineering.*
