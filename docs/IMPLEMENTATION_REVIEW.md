# Implementation Review: Roadmap & Security

This document summarizes the security measures and checks applied to the implemented features.

## 1. Bulk Alerts API (`PATCH /api/v1/alerts/bulk`)

### Security
- **Auth:** Requires `alerts:bulk_update` permission (analyst, senior_analyst, admin). Viewer is 403.
- **Reassignment:** Assigning to another user requires `alerts:assign` and non-empty `assign_comment`.
- **Validation:** 
  - `alert_ids`: 1–200 items, no duplicates, pattern `^[a-zA-Z0-9\-]{1,36}$`.
  - At least one of `status` or `assigned_to` required.
  - `status` must be in allowed map; `assigned_to` max 256 chars; `assign_comment` max 2000.
- **Audit:** Single `bulk_alert_update` log entry with counts and action type (no PII in details).
- **Route order:** `/bulk` registered before `/{alert_id}` so the path is matched correctly.

### Checks
- Tests: 401 without auth, 403 for viewer, 422 for empty ids / no action / invalid status, 200 with valid body.

---

## 2. Notifications (Slack, Email, Dispatcher)

### Security
- **Slack:** Webhook URL validated with regex (HTTPS, `hooks.slack.com` only). No secrets in logs. Message content sanitized and length-limited (3000 chars, 50 blocks).
- **Email:** Recipient and body sanitized; subject/body length limits. Credentials from config only. aiosmtplib optional (graceful fallback).
- **Dispatcher:** Only triggers for Critical/High severity. Payload built from sanitized fields. Exceptions caught and logged; never raised to caller.

### Checks
- Tests: Slack URL validation (valid/invalid), send with invalid URL returns False, mocked successful send.

---

## 3. Pull Connectors (Sentinel, GuardDuty, Runner)

### Security
- **Credentials:** All from `get_settings()` only (Azure, AWS). No hardcoded secrets.
- **Sentinel:** OAuth2 client credentials; token not logged. Query limited (24h, 500 rows). Errors logged without sensitive data.
- **GuardDuty:** boto3 client with config credentials. List/get findings only. Exceptions logged without creds.
- **Runner:** Uses shared `process_events`; enqueues enrichment and notifications via asyncio.create_task. No credential handling in runner.

### Checks
- Connectors are not auto-started in main (optional). Runner can be started explicitly or via scheduler.

---

## 4. Frontend Bulk UI

### Security
- Bulk action calls `bulkPatchAlerts` with user-selected IDs only (max 200 enforced by API).
- Confirm dialog before bulk update. No client-side bypass of permission (API enforces).
- Current user passed for “Assign to me” only when `user?.username` is set.

---

## 5. Core Ingest (`process_events`)

### Security
- All event dicts passed through `sanitize_log_data` before parse.
- Same decision engine and persist path as API ingest. No new code paths that skip sanitization.
- Returns `(ingested_ids, errors)`; caller commits and enqueues enrichment/notifications.

---

## 6. Git Hygiene

- **Script:** `scripts/git_hygiene.sh` removes `.env`, `soc_platform.db`, `repomix-output.xml`, `frontend/dist` from tracking.
- **.gitignore:** Already contains `.env`, `*.db`, `repomix-output.xml`, `frontend/dist/`. No change needed.

---

## 7. Dependencies

- **Added:** `aiosmtplib`, `boto3` for email and GuardDuty. No known CVEs introduced.
- **Removed:** `passlib[bcrypt]` (unused; argon2 only).

---

## 8. Summary

| Area           | Status |
|----------------|--------|
| Bulk API       | Auth, validation, audit, route order |
| Notifications  | URL validation, sanitization, no secrets in logs |
| Connectors     | Config-only creds, no secrets in logs |
| Frontend bulk  | Confirm dialog, API enforces permissions |
| Core ingest    | Shared path, sanitization preserved |
| Git hygiene    | Script + .gitignore verified |

All implemented features follow the security protocols: permission checks, input validation, no scope for credential leakage, and audit where appropriate.
