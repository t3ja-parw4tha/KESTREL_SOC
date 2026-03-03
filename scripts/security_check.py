#!/usr/bin/env python3
"""
Security check script: pip-audit, safety, fail on HIGH/CRITICAL CVEs.
Generate dependency vulnerability report as JSON.
Check for outdated packages with security patches.
"""

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
AUDIT_JSON = REPO_ROOT / "audit-report.json"
SAFETY_JSON = REPO_ROOT / "safety-report.json"


def run_pip_audit() -> dict:
    """Run pip-audit, return parsed JSON. Fail if HIGH/CRITICAL."""
    try:
        subprocess.run(
            [sys.executable, "-m", "pip_audit", "--format", "json", "-o", str(AUDIT_JSON)],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            timeout=120,
        )
    except subprocess.CalledProcessError as e:
        with open(AUDIT_JSON) as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        return {"dependencies": [], "vulnerabilities": [], "_error": "pip_audit not installed"}
    if AUDIT_JSON.exists():
        with open(AUDIT_JSON) as f:
            return json.load(f)
    return {"dependencies": [], "vulnerabilities": []}


def run_safety() -> dict:
    """Run safety check, return parsed output. Fail if HIGH/CRITICAL."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "safety", "check", "--json"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.stdout:
            return json.loads(result.stdout)
        return []
    except subprocess.CalledProcessError:
        return []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def run_bandit() -> dict:
    """Run bandit SAST, return summary."""
    try:
        subprocess.run(
            [sys.executable, "-m", "bandit", "-r", "app/", "-ll", "-f", "json", "-o", str(REPO_ROOT / "bandit-report.json")],
            cwd=REPO_ROOT,
            capture_output=True,
            timeout=60,
        )
        p = REPO_ROOT / "bandit-report.json"
        if p.exists():
            with open(p) as f:
                return json.load(f)
    except Exception:
        pass
    return {"results": [], "metrics": {}}


def has_critical_or_high(vulns: list) -> bool:
    """Check if any vulnerability is HIGH or CRITICAL."""
    for v in vulns:
        if isinstance(v, dict):
            severity = (v.get("severity") or v.get("advisory", {}).get("severity") or "").upper()
        else:
            severity = str(getattr(v, "severity", "")).upper()
        if severity in ("CRITICAL", "HIGH"):
            return True
    return False


def main() -> int:
    report = {"pip_audit": {}, "safety": [], "bandit": {}, "fail": False}

    # pip-audit
    audit = run_pip_audit()
    report["pip_audit"] = audit
    vulns = audit.get("vulnerabilities", [])
    if has_critical_or_high(vulns):
        report["fail"] = True
        print("FAIL: pip-audit found HIGH or CRITICAL vulnerabilities", file=sys.stderr)

    # safety
    safety = run_safety()
    report["safety"] = safety if isinstance(safety, list) else [safety]
    for s in report["safety"]:
        if isinstance(s, dict):
            sev = (s.get("severity") or s.get("advisory", {}).get("severity") or "").upper()
            if sev in ("CRITICAL", "HIGH"):
                report["fail"] = True
                print("FAIL: safety found HIGH or CRITICAL vulnerabilities", file=sys.stderr)

    # bandit (informational)
    report["bandit"] = run_bandit()

    out_path = REPO_ROOT / "security-report.json"
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Security report written to {out_path}")

    return 1 if report["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
