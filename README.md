# KESTREL
> AI-assisted SOC triage and detection platform

Named after the kestrel — the only bird of prey that hovers perfectly still while locking onto its target.

---

## What Is KESTREL

KESTREL is an open-source AI-assisted SOC platform that:
- Ingests security logs from multiple sources
- Maps alerts to MITRE ATT&CK techniques automatically  
- Runs a decision engine for risk scoring and correlation
- Uses LLM-powered AI to triage and summarize alerts
- Provides a React dashboard for analyst workflows

---

## Architecture

- **Backend**: FastAPI + SQLAlchemy async + SQLite/PostgreSQL  
- **Frontend**: React + Vite + TailwindCSS + Recharts  
- **Auth**: JWT RS256 + argon2 password hashing + RBAC  
- **AI**: OpenAI GPT-4o-mini / Anthropic Claude / Azure OpenAI (configurable)

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Git

### 1. Clone and setup

```bash
git clone https://github.com/yourname/kestrel
cd kestrel
python -m venv .venv

# Windows
.venv\Scripts\activate

# Mac/Linux
source .venv/bin/activate

pip install -r requirements/base.txt
```

### 2. Configure environment

```bash
cp .env.example .env   # or: copy .env.example .env on Windows
```

Edit `.env` and set at minimum:

```env
SECRET_KEY=your-random-secret-key-here
DATABASE_URL=sqlite:///./kestrel.db
```

For production, you should use PostgreSQL (and enable SSL):

```env
DATABASE_URL=postgresql+psycopg2://user:password@host:5432/kestrel
```

### 3. Setup AI provider (choose one)

By default KESTREL will fall back to rule-based summaries if no AI key is configured.

#### OpenAI (recommended)

```env
AI_PROVIDER=openai
OPENAI_API_KEY=sk-your-openai-api-key
```

#### Anthropic Claude

```env
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-your-key
```

#### Azure OpenAI

```env
AI_PROVIDER=azure
AZURE_OPENAI_API_KEY=your-key
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com
```

### 4. Setup log source integrations (optional)

#### Microsoft Sentinel

```env
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-app-client-id
AZURE_CLIENT_SECRET=your-client-secret
LOGANALYTICS_WORKSPACE_ID=your-workspace-id
```

#### AWS GuardDuty

```env
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=us-east-1
```

#### Threat Intelligence

```env
VIRUSTOTAL_API_KEY=your-vt-api-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
```

#### Notifications

```env
SLACK_WEBHOOK_URL=https://hooks.slack.com/your-webhook
```

### 5. Initialize database

```bash
alembic upgrade head
```

### 6. Create admin user

```bash
python -m scripts.create_admin --username admin --password "YourPassword123!!"
```

### 7. Load sample data (optional)

```bash
python -m scripts.seed_data
```

### 8. Start backend

```bash
uvicorn app.main:app --reload --port 8000
```

### 9. Start frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173/login` and log in with the admin credentials you created.

---

## Log Source Integration

### Supported Sources

| Source              | Type    | Auth Method             |
|---------------------|---------|-------------------------|
| Microsoft Sentinel  | SIEM    | Azure Service Principal |
| AWS GuardDuty       | Cloud   | AWS IAM Keys            |
| Microsoft Defender  | EDR     | Azure Service Principal |
| Suricata            | IDS/IPS | File/Syslog             |
| Snort               | IDS/IPS | File/Syslog             |
| Windows Event Log   | OS      | WinRM/Agent             |
| Syslog              | Generic | UDP/TCP 514             |
| Zeek                | Network | File/API                |

### Sending Logs via API

Send normalized events to `/api/v1/ingest` with a Bearer token:

```bash
curl -X POST http://localhost:8000/api/v1/ingest \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "Sentinel",
    "events": [{
      "AlertType": "BruteForce",
      "Severity": "High",
      "AlertName": "Multiple failed logins",
      "SourceIP": "185.220.101.45"
    }]
  }'
```

The backend will:
- Parse the event with the source-specific parser
- Normalize into a `NormalizedAlert`
- Map to MITRE ATT&CK techniques
- Run the decision engine (risk score, correlation)
- Persist it as an `Alert` and `AlertDecision`

---

## User Roles

KESTREL ships with 4 roles:

| Role           | Permissions                                        |
|----------------|----------------------------------------------------|
| **admin**      | Full access, create users, manage sources & config |
| **senior_analyst** | View all, run AI, manage alerts & incidents   |
| **analyst**    | View and update alerts & incidents                 |
| **viewer**     | Read-only access                                   |

### Create a new user (admin only)

```http
POST /api/v1/auth/users
Authorization: Bearer ADMIN_TOKEN
Content-Type: application/json

{
  "username": "analyst1",
  "password": "SecurePass2026!!",
  "role": "analyst"
}
```

---

## AI Configuration

KESTREL uses AI to:

- Summarize alert context in plain English
- Extract key facts (severity, affected assets, IOCs)
- Suggest remediation steps
- Recommend next actions for analysts

If no AI provider is configured (no key), KESTREL falls back to a **rule-based summary** so the UI never shows empty analysis.

To enable real AI triage, add your provider key to `.env`, restart the backend, then click **“Run AI Analysis”** on any alert detail page.

---

## Running Tests

### Unit / Integration / Security Tests

```bash
pytest tests/ -v
```

You can also run specific groups (if configured):

```bash
pytest tests/decision_engine -v
pytest tests/security -v
pytest tests/integration -v
```

### CI Helpers

There is a helper script that can be wired to run all checks (if present):

```bash
python -m scripts.run_tests
```

---

## API Documentation

- Swagger UI: `http://localhost:8000/docs`  
- ReDoc: `http://localhost:8000/redoc`

Auth is via Bearer token (`Authorization: Bearer <access_token>`). You can obtain a token from `/api/v1/auth/login`.

---

## Docker

Run the platform via Docker Compose:

```bash
cd docker
docker compose up --build
```

Services (depending on your compose file):

- **Backend**: `http://localhost:8000`
- **Frontend**: `http://localhost:3000` (or served via the backend in production)

---

## Project Structure

```text
kestrel/
├── app/
│   ├── ai/          # AI provider clients and prompts
│   ├── api/         # FastAPI routers (auth, alerts, incidents, ingest, ai)
│   ├── core/        # Decision engine, parsers, MITRE mapping, detection rules
│   ├── enrichment/  # VirusTotal, AbuseIPDB, threat feeds
│   ├── models/      # SQLAlchemy models
│   ├── security/    # Auth, RBAC, JWT, middleware, sanitization
│   └── connectors/  # Sentinel, GuardDuty, Defender, etc.
├── frontend/
│   ├── src/
│   │   ├── api/       # Typed API client functions
│   │   ├── pages/     # React pages (Dashboard, Alerts, Incidents, MITRE, Sources)
│   │   ├── components/# Reusable UI and domain components
│   │   └── security/  # Auth context, route guards
│   └── templates/     # Jinja2 templates (for server-rendered views)
├── tests/             # Pytest unit, integration, security tests
├── scripts/           # Seed data, admin creation, security checks
└── docker/            # Dockerfile and docker-compose configs
```

---

## Security Notes

KESTREL is designed with secure defaults suitable for SOC environments:

- **Password storage**: argon2id via `argon2-cffi` (OWASP recommended)
- **JWT**: RS256 asymmetric signing; private key never leaves the server
- **RBAC**: Fine-grained permissions per role; enforced on every protected route
- **Rate limiting**: Per-IP / per-key rate limits with blocking thresholds
- **Account lockout**: Progressive delays and lockout after repeated failed logins
- **Input sanitization**:
  - XSS filtering using `bleach` and HTML escaping
  - JSON depth / size limits to prevent deep or oversized payloads
  - Path traversal protection for any file-based access
- **CSRF**: CSRF token support for state-changing operations (when using cookies)
- **Audit logging**: Every analyst action and access-denied event is written to an `AuditLog` table
- **Headers**: Strict security headers (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, etc.)

For production, you should also:

- Terminate TLS in front of KESTREL (reverse proxy / ingress)
- Set `ENVIRONMENT=production` and use PostgreSQL with SSL
- Rotate secrets regularly and store them in a proper secret manager

---

## Built With

- **Backend**: FastAPI, SQLAlchemy, Alembic, `argon2-cffi`, `python-jose`
- **Frontend**: React, Vite, TailwindCSS, Recharts, TanStack Query
- **Templating / UI**: Jinja2, HTMX, Chart.js
- **Observability**: Prometheus metrics, Grafana dashboards (optional)

---

## License

See the repository `LICENSE` file for details.
