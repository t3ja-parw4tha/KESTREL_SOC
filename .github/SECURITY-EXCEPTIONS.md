# Security Exception Policy

Security exceptions are temporary risk acceptances and must be time-bounded, auditable, and approved.

## Eligibility

An exception may be requested only when all conditions are true:

1. A production-blocking security finding cannot be remediated before the release window.
2. A compensating control is in place and verifiable.
3. A remediation issue is already opened with an owner and due date.

## Required Fields

Every exception record must include:

- Finding ID: tool + rule/CVE identifier
- Severity: `Critical`, `High`, or `Medium`
- Scope: affected services/routes/files
- Risk owner: name + team
- Security approver: name + team
- Compensating control: concrete technical/operational control
- Expiry: ISO date, max 30 days from approval
- Remediation ticket: issue/PR link

## Approval Workflow

1. Engineer creates exception request in PR description using the template below.
2. Security approver explicitly approves in PR review.
3. PR must include `security-exception` label.
4. Exception is logged in release notes and changelog.

## Template

```text
SECURITY EXCEPTION
------------------
Finding:          <tool> finding ID / CVE / rule name
Severity:         Critical | High | Medium
Scope:            <services/routes/files>
Description:      <exact vulnerability description>
Risk accepted by: <risk owner name + email>
Security approver:<security approver name + email>
Compensating control: <what prevents exploitation until remediated>
Expiry date:      <YYYY-MM-DD, <= 30 days>
Remediation issue: <GitHub issue or PR URL>
PR:               <PR number>
```

## Enforcement Rules

- Expired exceptions are invalid and block merge.
- Critical findings cannot be excepted without Director/Head-of-Security approval.
- Any exception without all required fields is invalid and treated as no exception.

## Operational Checks

- Weekly review of active exceptions by security team.
- CI/CD gate must fail when an exception is expired or malformed.
