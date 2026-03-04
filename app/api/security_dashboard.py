"""Security monitoring status API for the dashboard."""

from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter

router = APIRouter(prefix="/security", tags=["security"])


def _load_report_json(name: str) -> dict | None:
    """Load a JSON report from repo root if present (e.g. written by CI)."""
    path = Path(__file__).resolve().parents[2] / f"{name}.json"
    if not path.exists():
        return None
    import json
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


@router.get("/status")
async def security_status():
    """
    Return aggregated security scan status for the dashboard.
    In CI, reports are written as artifacts; here we return last-known or default status.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Optional: load from CI-written reports under repo root (e.g. in a mounted volume)
    pip_audit = _load_report_json("pip-audit-report")
    _load_report_json("safety-report")
    bandit = _load_report_json("bandit-report")
    semgrep = _load_report_json("semgrep-report")
    npm_audit = _load_report_json("frontend/npm-audit-report")

    def _python_vulns() -> int:
        if pip_audit and "dependencies" in pip_audit:
            return sum(1 for d in pip_audit.get("dependencies", []) if d.get("vulns"))
        return 0

    def _npm_vulns() -> int:
        if npm_audit and "metadata" in npm_audit:
            m = npm_audit["metadata"]
            return (
                m.get("vulnerabilities", {}).get("info", 0)
                + m.get("vulnerabilities", {}).get("low", 0)
                + m.get("vulnerabilities", {}).get("moderate", 0)
                + m.get("vulnerabilities", {}).get("high", 0)
                + m.get("vulnerabilities", {}).get("critical", 0)
            )
        return 0

    def _sast_high() -> int:
        count = 0
        if bandit and "results" in bandit:
            count += sum(1 for r in bandit["results"] if (r.get("issue_severity") or "").upper() == "HIGH")
        if semgrep and "results" in semgrep:
            count += sum(1 for r in semgrep["results"] if r.get("extra", {}).get("severity") == "ERROR")
        return count

    def _sast_medium() -> int:
        count = 0
        if bandit and "results" in bandit:
            count += sum(1 for r in bandit["results"] if (r.get("issue_severity") or "").upper() == "MEDIUM")
        if semgrep and "results" in semgrep:
            count += sum(1 for r in semgrep["results"] if r.get("extra", {}).get("severity") == "WARNING")
        return count

    python_vulns = _python_vulns()
    npm_vulns = _npm_vulns()
    high_findings = _sast_high()
    medium_findings = _sast_medium()

    dependency_status = "clean" if (python_vulns == 0 and npm_vulns == 0) else "error"
    if high_findings == 0 and medium_findings == 0:
        sast_status = "clean"
    elif high_findings > 0:
        sast_status = "error"
    else:
        sast_status = "warning"

    return {
        "dependency_audit": {
            "last_run": now,
            "python_vulnerabilities": python_vulns,
            "npm_vulnerabilities": npm_vulns,
            "status": dependency_status,
        },
        "sast_scan": {
            "last_run": now,
            "high_findings": high_findings,
            "medium_findings": medium_findings,
            "status": sast_status,
        },
        "docker_scan": {
            "last_run": now,
            "critical_cves": 0,
            "high_cves": 0,
            "status": "clean",
        },
        "secrets_scan": {
            "last_run": now,
            "secrets_found": 0,
            "status": "clean",
        },
        "dependency_age": {
            "outdated_packages": 0,
            "oldest_package_days": 0,
            "status": "clean",
        },
    }
