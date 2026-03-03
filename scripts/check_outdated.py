#!/usr/bin/env python3
"""
Consume `pip list --outdated --format=json` from stdin or run pip and report
outdated packages. Exits with 1 if any outdated packages (for CI).
"""
import json
import subprocess
import sys
from pathlib import Path


def get_outdated_json() -> list[dict]:
    """Run pip list --outdated --format=json and return parsed list."""
    result = subprocess.run(
        [sys.executable, "-m", "pip", "list", "--outdated", "--format=json"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0 and result.stderr and "WARNING" not in result.stderr:
        print(result.stderr, file=sys.stderr)
        return []
    return json.loads(result.stdout) if result.stdout.strip() else []


def main() -> int:
    outdated = get_outdated_json()
    if not outdated:
        print("All packages are up to date.")
        return 0
    print(f"Found {len(outdated)} outdated package(s):")
    for pkg in outdated:
        name = pkg.get("name", "?")
        current = pkg.get("version", "?")
        latest = pkg.get("latest_version", "?")
        print(f"  {name}: {current} -> {latest}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
