# Contributing to KESTREL

Thank you for your interest in contributing. This document gives a short overview of how to get started.

## Development setup

1. **Clone and install**
   - Python 3.11+
   - Backend: `pip install -e ".[dev]"` (or use `requirements/base.txt` / `requirements/dev.txt` as in README)
   - Frontend: `cd frontend && npm install`

2. **Environment**
   - Copy `.env.example` to `.env` and set at least `SECRET_KEY`, `DATABASE_URL`, and any API keys you need (e.g. OpenAI for AI triage).

3. **Run**
   - Backend: `uvicorn app.main:app --reload --port 8000`
   - Frontend: `npm run dev` (Vite, typically http://localhost:5173)

## Code standards

- **Backend:** Python style follows Ruff and mypy; run `ruff check .` and `mypy app` before submitting.
- **Frontend:** ESLint; run `npm run lint` in `frontend/`.
- **Tests:** Add or extend tests for new behavior. Backend uses pytest; aim to keep coverage meaningful for critical paths.

## Pull requests

- Open a PR against the default branch with a clear description of the change.
- Ensure CI (if configured) passes.
- For features or API changes, consider updating README and CHANGELOG.

## Reporting issues

- Use the issue tracker for bugs and feature requests; include steps to reproduce where relevant.

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (see LICENSE).
