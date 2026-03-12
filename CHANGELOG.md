# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-03-07

### Added

- LICENSE file (MIT)
- AI provider dispatch: Settings `AI_PROVIDER` (openai, anthropic, azure) is now respected
- Anthropic (Claude) provider implementation for AI triage
- Azure OpenAI provider stub (config respected; implementation TODO)
- CORS allowed origin for Vite dev server (`http://localhost:5173`)
- CHANGELOG.md and CONTRIBUTING.md

### Changed

- Version set to 1.0.0 in pyproject.toml and frontend package.json
- SQLAlchemy models use `sqlalchemy.types.JSON` instead of SQLite-specific JSON (PostgreSQL-ready)
- Password hashing: only argon2 (argon2-cffi) in use; removed unused passlib/bcrypt
- Removed `bcrypt_rounds` from config
- Docker Compose: removed deprecated `version` key
- Startup: application fails fast if `SECRET_KEY` is still the default in non-debug mode

### Security

- Production startup now requires a non-default SECRET_KEY

---

## [0.1.0] - Initial release

- SOC dashboard, alert management, AI triage, MITRE coverage, RBAC, multi-source ingest, and related features (see README).
