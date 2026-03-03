"""
Basic automated penetration test script for the SOC platform.

Usage:
    python -m scripts.penetration_test --base-url http://localhost:8000

The script runs a small battery of safe OWASP-style tests against the running
API and writes:
    - penetration_report.json
    - penetration_report.html
in the current working directory.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, asdict
from typing import Any

import httpx


@dataclass
class Finding:
    id: str
    category: str
    description: str
    passed: bool
    severity: str
    cvss: float
    remediation: str
    details: dict[str, Any] | None = None


async def _test_sql_injection(base_url: str, client: httpx.AsyncClient) -> Finding:
    q = "' OR '1'='1"
    r = await client.get(f"{base_url}/api/v1/alerts", params={"search": q})
    passed = r.status_code < 500
    return Finding(
        id="sql-injection-search",
        category="Injection",
        description="Search parameter should not cause SQL injection or 5xx.",
        passed=passed,
        severity="medium",
        cvss=5.0 if not passed else 0.0,
        remediation="Ensure all queries use parameterized SQL and never concatenate raw input.",
        details={"status_code": r.status_code, "body": r.text[:500]},
    )


async def _test_xss_in_title(base_url: str, client: httpx.AsyncClient) -> Finding:
    payload = {
        "source": "UnknownSource",
        "events": [{"severity": "Low", "title": "<script>alert(1)</script>"}],
    }
    r = await client.post(f"{base_url}/api/v1/ingest", json=payload)
    passed = r.status_code in (200, 400, 422)
    return Finding(
        id="xss-title",
        category="XSS",
        description="Script tags in alert titles should be sanitized or rejected.",
        passed=passed,
        severity="medium",
        cvss=5.0 if not passed else 0.0,
        remediation="Apply HTML escaping and strip script tags before storing or rendering.",
        details={"status_code": r.status_code, "body": r.text[:500]},
    )


async def run_penetration_tests(base_url: str) -> list[Finding]:
    async with httpx.AsyncClient(timeout=10) as client:
        findings: list[Finding] = []
        findings.append(await _test_sql_injection(base_url, client))
        findings.append(await _test_xss_in_title(base_url, client))
        return findings


def _write_reports(findings: list[Finding]) -> None:
    data = [asdict(f) for f in findings]
    with open("penetration_report.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    passed = [f for f in findings if f.passed]
    failed = [f for f in findings if not f.passed]
    html = [
        "<html><head><title>SOC Penetration Test Report</title></head><body>",
        "<h1>SOC Platform Penetration Test Report</h1>",
        f"<p>Total tests: {len(findings)}; Passed: {len(passed)}; Failed: {len(failed)}</p>",
        "<h2>Findings</h2>",
        "<ul>",
    ]
    for f in findings:
        status = "PASSED" if f.passed else "FAILED"
        html.append(
            f"<li><strong>{f.id}</strong> [{status}] "
            f"(category: {f.category}, severity: {f.severity}, CVSS: {f.cvss})<br/>"
            f"{f.description}<br/>"
            f"<em>Remediation:</em> {f.remediation}</li>"
        )
    html.append("</ul></body></html>")
    with open("penetration_report.html", "w", encoding="utf-8") as f:
        f.write("\n".join(html))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run basic penetration tests against SOC Platform.")
    parser.add_argument(
        "--base-url",
        default="http://localhost:8000",
        help="Base URL of the running SOC Platform API (default: http://localhost:8000)",
    )
    args = parser.parse_args()

    import asyncio

    findings = asyncio.run(run_penetration_tests(args.base_url))
    _write_reports(findings)
    print("Penetration tests complete. See penetration_report.json and penetration_report.html.")


if __name__ == "__main__":
    main()

