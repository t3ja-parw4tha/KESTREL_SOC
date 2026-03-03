# Dependency and security targets. Use from repo root.
# On Windows use: make (with Make installed) or run commands manually.

.PHONY: security compile-deps update-deps outdated audit-frontend update-frontend

# Run all Python security checks
security:
	bandit -r app/ -ll
	pip-audit -r requirements/base.txt
	safety check -r requirements/base.txt
	@echo "Semgrep: run in CI (no Windows support)"

# Compile pinned deps from .in files
compile-deps:
	pip-compile requirements/base.in -o requirements/base.txt
	pip-compile requirements/dev.in -o requirements/dev.txt -c requirements/base.txt

# Update all deps to latest safe versions
update-deps:
	pip-compile --upgrade requirements/base.in -o requirements/base.txt
	pip-compile --upgrade requirements/dev.in -o requirements/dev.txt -c requirements/base.txt
	pip-audit -r requirements/base.txt
	pytest

# Check for outdated packages
outdated:
	python scripts/check_outdated.py

# --- Frontend (run from repo root) ---

audit-frontend:
	cd frontend && npm audit --audit-level=high

update-frontend:
	cd frontend && npx npm-check-updates -u
	cd frontend && npm install
	cd frontend && npm audit --audit-level=high
	cd frontend && npm test
