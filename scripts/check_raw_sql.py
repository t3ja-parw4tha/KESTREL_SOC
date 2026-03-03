#!/usr/bin/env python3
"""
CI check: fail if raw SQL or string formatting is used with execute().

SQL injection prevention: all DB access must use SQLAlchemy ORM or parameterized
statements. This script fails if it finds patterns like:
  - execute("SELECT ...")
  - execute(f"...")
  - execute("... %s ..." % x)
  - conn.execute("...")
"""

import re
import sys
from pathlib import Path

# Patterns that suggest raw SQL with string formatting (high risk)
EXECUTE_STRING_PATTERNS = [
    re.compile(r"\.execute\s*\(\s*f[\"']"),   # f" or f'
    re.compile(r"\.execute\s*\(\s*[\"'][^\"']*%"),  # "..." % ...
    re.compile(r"\.execute\s*\(\s*[\"'][^\"']*\+"),  # "..." + ...
    re.compile(r"\.execute\s*\(\s*[\"'][^\"']*\.format\s*\("),  # "".format(
    re.compile(r"\.execute\s*\(\s*[\"'][^\"']*\{\s*"),  # "..{}..".format or f"..{"
]

# Allowed: execute(select(...)), execute(stmt), text("...") with bound params only is OK but we flag any long raw string
RAW_EXECUTE_PATTERN = re.compile(
    r"\.execute\s*\(\s*[\"']([^\"']{50,})[\"']\s*\)"  # long string literal = likely raw SQL
)


def check_file(path: Path) -> list[tuple[int, str]]:
    violations = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        if "execute(" not in line:
            continue
        for pat in EXECUTE_STRING_PATTERNS:
            if pat.search(line):
                violations.append((i, line.strip()[:100]))
                break
        if RAW_EXECUTE_PATTERN.search(line):
            violations.append((i, "Possible raw SQL string in execute(): " + line.strip()[:80]))
    return violations


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    app_dir = repo_root / "app"
    if not app_dir.is_dir():
        return 0
    total = 0
    for py in app_dir.rglob("*.py"):
        violations = check_file(py)
        if violations:
            rel = py.relative_to(repo_root)
            print(f"{rel}:")
            for line_no, msg in violations:
                print(f"  L{line_no}: {msg}")
            total += len(violations)
    if total:
        print("\nFAIL: Use SQLAlchemy ORM or parameterized queries only. No raw SQL with string formatting.")
        return 1
    print("OK: No raw SQL execute() patterns found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
