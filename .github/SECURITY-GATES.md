# Security Gates And Merge Policy

This repository follows fail-closed security delivery.

## Required Branch Rules (GitHub Settings)
Apply these to branch `dev`:

1. Require a pull request before merging.
2. Require approvals (minimum 2 for security-sensitive changes).
3. Require review from Code Owners.
4. Dismiss stale approvals when new commits are pushed.
5. Require status checks to pass before merging.
6. Do not allow bypassing the above settings.
7. Restrict who can push to `dev` (no direct pushes).

## Required Status Checks
Mark these as required in branch protection:

- `CI / lint`
- `CI / type-check`
- `CI / test`
- `CI / security-tests`
- `Security Scan / sast`
- `Dependency Security Audit / python-audit`
- `Dependency Security Audit / frontend-audit`
- `CodeQL / analyze (python)`
- `CodeQL / analyze (javascript-typescript)`
- `DAST And API Security / api-security-smoke`
- `DAST And API Security / dast-zap-baseline`

Automation: apply the repository branch policy with `scripts/enforce_branch_protection.ps1` using a `GITHUB_TOKEN` that has repository administration permission.

## Fail-Close Policy

All security gates are configured fail-closed:

| Tool | Gate | Action on Finding |
|---|---|---|
| Bandit | Medium+ severity/confidence | CI job exits 1 — blocks merge |
| pip-audit | Any known CVE | CI job exits 1 — blocks merge |
| Safety | Any vulnerability in requirements | CI job exits 1 — blocks merge |
| Semgrep | Any OWASP/security-audit rule match | CI job exits 1 — blocks merge |
| npm audit | High or critical severity | CI job exits 1 — blocks merge |
| Trivy | Critical or High in container image | CI job exits 1 — blocks merge |
| TruffleHog | Any verified secret | CI job exits 1 — blocks merge |
| API Smoke (DAST) | Unexpected authz response | CI job exits 1 — blocks merge |

## Security Exceptions (Time-Bounded)

A security exception **must** include all of the following — no exception without all fields:

```
SECURITY EXCEPTION
------------------
Finding:          <tool> finding ID / CVE / rule name
Severity:         Critical | High | Medium
Description:      <exact vulnerability description>
Risk accepted by: <security approver name + email>
Compensating control: <what prevents exploitation until remediated>
Expiry date:      <ISO date, maximum 30 days from approval>
Remediation issue: <GitHub issue or PR URL>
PR:               <PR number where this exception is declared>
```

Exception template is enforced via PR template checklist item SC-9. Detailed process and template live in `.github/SECURITY-EXCEPTIONS.md`. Expired exceptions block the next PR touching the same file path.

## Releasing With Outstanding Findings

Deployments to production are blocked when:
- Any required check is failing
- Any open exception has passed its expiry date
- A critical/high Trivy or TruffleHog finding is unfixed

To unblock: either remediate the finding or follow the exception process above with a new expiry date.

## SC Checklist Verification Status (2026-03-15)

| Item | Description | Status | Evidence |
|---|---|---|---|
| SC-1 | Scope & Risk documented | ✅ Pass | SECURITY-IMPACT.md |
| SC-2 | Compliance mapping current | ✅ Pass | SECURITY-CONTROLS.md |
| SC-3 | Secure implementation verified | ✅ Pass | All API files audited |
| SC-4 | Secrets & data protection | ✅ Pass | No hardcoded secrets, logs redact sensitive values |
| SC-5 | Auditability — all actions logged | ✅ Pass | AuditLog in all security-relevant endpoints |
| SC-6 | Dependency scan clean | ✅ Pass | DEPENDENCY-AUDIT.md |
| SC-7 | Security tests added | ✅ Pass | tests/security/test_sc_security.py |
| SC-8 | Negative testing complete | ✅ Pass | tests/security/test_sc_security.py |
| SC-9 | CI gates pass | ✅ Pass | All workflows fail-closed |
| SC-10 | Security reviewer sign-off | ✅ Pass | SECURITY-REVIEW.md |
