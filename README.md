# KESTREL
> AI-assisted SOC triage and detection platform

Named after the kestrel — the only bird of prey that hovers perfectly still while locking onto its target.

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green)
![React](https://img.shields.io/badge/React-18-61DAFB)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## What Is KESTREL

KESTREL is an open-source AI-assisted SOC platform built for security analysts. It aggregates alerts from multiple log sources, automatically maps them to MITRE ATT&CK techniques, scores them with a decision engine, and uses LLM-powered AI to triage and summarize each alert — all through a dark-themed React dashboard.

**Key capabilities:**

- Multi-source log ingestion (Sentinel, GuardDuty, Suricata, Defender, Snort, Windows Event Log, Syslog, Zeek)
- Automatic MITRE ATT&CK technique mapping on every ingested alert
- Risk scoring and alert correlation via a decision engine
- AI-powered triage: plain-English summaries, key facts, remediation steps, next actions
- MITRE ATT&CK coverage heatmap with detection gap analysis
- IOC enrichment via VirusTotal and AbuseIPDB
- Role-based access control (admin, senior_analyst, analyst, viewer)
- Full settings UI — configure API keys and source connections without touching the terminal
- First-time setup wizard — no terminal needed to create your first admin account

---

## Screenshots

| Dashboard | Alert Detail | MITRE Coverage |
|-----------|-------------|----------------|
| Stats, severity donut, 7-day volume chart, recent alerts | 6-tab detail view with AI analysis, enrichment, timeline | Heatmap with detection gap analysis |

---

## Architecture

```text
┌─────────────────────────────────────────────────────┐
│                    React Frontend                    │
│   Dashboard · Alerts · Incidents · MITRE · Sources  │
│          Settings · Users · Setup Wizard            │
└────────────────────────┬────────────────────────────┘
                         │ HTTP / REST
┌────────────────────────▼────────────────────────────┐
│                  FastAPI Backend                     │
│  Auth (JWT RS256) · RBAC · Rate Limiting · Audit    │
├──────────┬──────────┬──────────┬────────────────────┤
│  Ingest  │  Alerts  │    AI    │   MITRE / Enrich   │
│  Router  │   CRUD   │ Summarize│   Coverage · IOC   │
├──────────┴──────────┴──────────┴────────────────────┤
│              Decision Engine · Parsers               │
│         Risk Score · Correlation · MITRE Map        │
├─────────────────────────────────────────────────────┤
│                    SQLite / PostgreSQL               │
└─────────────────────────────────────────────────────┘
         ▲                              ▲
┌────────┴────────┐          ┌─────────┴────────┐
│  Pull Connectors│          │  Push via /ingest │
│ Sentinel        │          │ Suricata · Snort  │
│ GuardDuty       │          │ Windows Event Log │
│ Defender        │          │ Syslog · Zeek     │
└─────────────────┘          └──────────────────┘
```

**Stack:**
- **Backend**: FastAPI + SQLAlchemy async + Alembic + argon2-cffi + python-jose
- **Frontend**: React 18 + Vite + TailwindCSS + Recharts + TanStack Query
- **Auth**: JWT RS256 asymmetric signing + argon2id password hashing + RBAC
- **AI**: OpenAI GPT-4o-mini / Anthropic Claude / Azure OpenAI (configurable, falls back to rule-based)
- **Observability**: Prometheus metrics + Grafana dashboards (optional)

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Git

### 1. Clone and set up Python environment

```bash
git clone https://github.com/t3ja-parw4tha/KESTREL_SOC.git
cd KESTREL_SOC

python -m venv .venv

# Windows
.venv\Scripts\activate

# Mac/Linux
source .venv/bin/activate

pip install -r requirements/base.txt
```

### 2. Configure environment

```bash
# Windows
copy .env.example .env

# Mac/Linux
cp .env.example .env
```

Open `.env` and set at minimum:

```env
SECRET_KEY=your-random-64-char-secret-key
DATABASE_URL=sqlite:///./kestrel.db
```

Everything else (AI keys, source credentials) can be configured later through the **Settings UI** — no terminal required.

### 3. Initialize the database

```bash
alembic upgrade head
```

### 4. Start the backend

```bash
uvicorn app.main:app --reload --port 8000
```

### 5. Start the frontend

```bash
cd frontend
npm install
npm run dev
```

### 6. Open KESTREL

Go to `http://localhost:5173`

You’ll see the **landing page**. Use **Get started** to run the first-time **Setup Wizard** (create admin account, optional AI provider), or **Sign in** if you’ve already set up. On first launch with no admin account, visiting the app will redirect you to the Setup Wizard.

---

## First-Time Setup Wizard

On a fresh install with no database, KESTREL shows a 3-step wizard:

1. **Create Admin Account** — set username and password (min 12 chars)
2. **Configure AI Provider** — enter OpenAI or Anthropic key (optional, can skip)
3. **Done** — go to login

No terminal commands needed. All credentials are saved to your local `.env` file and never pushed to the repository.

If you prefer the terminal:

```bash
python -m scripts.create_admin --username admin --password "YourPassword123!!"
```

---

## Settings UI

Everything in KESTREL is configurable through **Settings** (bottom of the sidebar, admin only):

### AI Configuration tab

| Setting | Description |
|---------|-------------|
| AI Provider | `openai`, `anthropic`, or `azure` |
| OpenAI API Key | `sk-...` from platform.openai.com |
| Anthropic API Key | `sk-ant-...` from console.anthropic.com |
| Azure OpenAI Key + Endpoint | Enterprise Azure deployment |

Without a key, KESTREL falls back to rule-based summaries automatically — the UI never shows empty analysis.

### Source Integrations tab

| Source | Credentials Needed |
|--------|-------------------|
| Microsoft Sentinel | Tenant ID, Client ID, Client Secret, Workspace ID |
| AWS GuardDuty | Access Key ID, Secret Access Key, Region |
| VirusTotal | API key (free tier: 500/day) |
| AbuseIPDB | API key (free tier: 1000/day) |
| Suricata / Snort | EVE JSON path (push via `/api/v1/ingest`) |

Each section has a **Save** button and a **Test Connection** button that validates the credentials live.

### Notifications tab

| Setting | Description |
|---------|-------------|
| Slack Webhook URL | Sends critical alert notifications |
| Alert Email | Email address for alert notifications |

All settings are saved to your local `.env` file only — they are never committed to the repository (`.env` is in `.gitignore`).

---

## Log Source Integration

### Supported Sources

| Source | Type | Connection Mode |
|--------|------|----------------|
| Microsoft Sentinel | SIEM | Pull — KQL query via Log Analytics API every 5 min |
| AWS GuardDuty | Cloud | Pull — boto3 list_findings every 5 min |
| Microsoft Defender | EDR | Push via `/api/v1/ingest` |
| Suricata | IDS/IPS | Push via `/api/v1/ingest` or EVE JSON file |
| Snort | IDS/IPS | Push via `/api/v1/ingest` |
| Windows Event Log | OS | Push via `/api/v1/ingest` |
| Syslog | Generic | Push via `/api/v1/ingest` |
| Zeek | Network | Push via `/api/v1/ingest` |

### Sending Logs via API (Push Model)

```bash
# Get a token
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "YourPassword123!!"}'

# Ingest a Sentinel-style alert
curl -X POST http://localhost:8000/api/v1/ingest \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "Sentinel",
    "events": [{
      "AlertType": "BruteForce",
      "Severity": "High",
      "AlertName": "Multiple failed logins detected",
      "Category": "Auth",
      "SourceIP": "185.220.101.45",
      "UserPrincipalName": "jdoe@contoso.com"
    }]
  }'
```

**What happens on ingest:**
1. Source-specific parser normalizes the event
2. MITRE ATT&CK techniques are mapped automatically
3. Decision engine calculates risk score and checks for correlation
4. IOC enrichment runs in the background (VirusTotal, AbuseIPDB)
5. Alert is persisted and appears on the dashboard immediately

### PowerShell (Windows)

```powershell
$r = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/auth/login" `
  -Method POST -ContentType "application/json" `
  -Body '{"username":"admin","password":"YourPassword123!!"}'

$token = $r.access_token
$h = @{ "Authorization" = "Bearer $token"; "Content-Type" = "application/json" }

Invoke-RestMethod -Uri "http://localhost:8000/api/v1/ingest" `
  -Method POST -Headers $h `
  -Body '{"source":"WindowsEventLog","events":[{"EventID":4625,"EventData":{"TargetUserName":"administrator","IpAddress":"10.0.0.5"}}]}'
```

### Load Sample Data

```bash
python -m scripts.seed_data
```

Ingests 15 realistic alerts covering brute force, lateral movement, credential dumping, ransomware, CobaltStrike beacon, crypto mining, SQL injection, and more.

---

## MITRE ATT&CK Coverage

KESTREL maps every ingested alert to MITRE ATT&CK techniques automatically based on:

- Alert type and category
- Windows Event IDs
- IDS/IPS signatures
- Process names and command lines

The **MITRE Coverage** page shows:
- A full heatmap of all 12 tactics and their techniques
- Coverage percentage (techniques with detections / total)
- **Detection Gaps** — high-priority techniques with zero detections, shown as red cards

Example gap analysis output:

```text
T1078  Valid Accounts          Initial Access    → No detections
T1053  Scheduled Task          Persistence       → No detections
T1055  Process Injection       Defense Evasion   → No detections
```

This is useful for explaining detection coverage to clients and identifying blind spots in your security posture — a core use case in GRC and consulting engagements.

---

## User Management

KESTREL supports 4 roles managed entirely through the UI:

| Role | Permissions |
|------|-------------|
| `admin` | Full access — create/edit/deactivate users, manage settings, view audit log |
| `senior_analyst` | View all alerts and incidents, run AI triage, manage alert status |
| `analyst` | View and update alerts and incidents |
| `viewer` | Read-only access across all pages |

### Create a user via UI

Settings → Users tab → Manage Users → + Create User

### Create a user via API

```http
POST /api/v1/auth/users
Authorization: Bearer ADMIN_TOKEN
Content-Type: application/json

{
  "username": "analyst1",
  "password": "SecurePass2026!!",
  "role": "analyst",
  "email": "analyst1@yourorg.com"
}
```

### Update role or deactivate via API

```http
PATCH /api/v1/auth/users/{user_id}
Authorization: Bearer ADMIN_TOKEN
Content-Type: application/json

{"role": "senior_analyst"}
```

---

## AI Triage

KESTREL uses AI to analyze each alert and produce:

| Field | Description |
|-------|-------------|
| Summary | Plain-English explanation of what happened and why it matters |
| Key Facts | Severity, source, category, affected asset, user |
| Affected | Asset ID, user ID, source IP, destination IP |
| Evidence | Raw log preview, correlated alert IDs |
| Remediation | Step-by-step actions to contain and resolve |
| Next Steps | Recommended analyst actions and escalation path |

**To run AI analysis:**
1. Go to any alert detail page
2. Click the **AI Analysis** tab
3. Click **Run AI Analysis**
4. Results appear within a few seconds and are cached for 24 hours

**Without an API key:** KESTREL shows a rule-based summary with a link to configure a real AI provider in Settings.

**Supported providers:**
- OpenAI GPT-4o-mini (recommended — fast, cheap, accurate)
- Anthropic Claude
- Azure OpenAI (enterprise)

---

## Running Tests

```bash
# Full test suite
pytest tests/ -v

# Security tests only
pytest tests/security/ -v

# Decision engine tests
pytest tests/test_decision_engine.py -v

# Detection rule tests
pytest tests/test_detection_rules.py -v
```

---

## API Documentation

Interactive API docs are available when the backend is running:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

All protected endpoints require `Authorization: Bearer <access_token>`.

Get a token:

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "YourPassword123!!"}'
```

---

## Docker

```bash
cd docker
docker compose up --build
```

Services:
- **Backend**: `http://localhost:8000`
- **Frontend**: `http://localhost:3000`
- **Prometheus** (optional): `http://localhost:9090`
- **Grafana** (optional): `http://localhost:3001`

---

## Project Structure

```text
kestrel/
├── app/
│   ├── ai/                  # AI provider clients (OpenAI, Anthropic, Azure)
│   │   ├── client.py        # Triage orchestrator
│   │   ├── prompts.py       # System and user prompt templates
│   │   └── providers/       # OpenAI, Anthropic, Azure implementations
│   ├── api/                 # FastAPI routers
│   │   ├── alerts.py        # Alert CRUD, status, comments, timeline
│   │   ├── auth.py          # Login, refresh, users, setup
│   │   ├── ai.py            # AI summarize endpoint
│   │   ├── ingest.py        # Multi-source ingest pipeline
│   │   ├── incidents.py     # Incident grouping and detail
│   │   ├── mitre.py         # MITRE coverage and techniques
│   │   ├── settings.py      # Settings read/write (.env)
│   │   └── sources.py       # Source connector status
│   ├── connectors/          # Pull connectors (Sentinel, GuardDuty, Defender)
│   ├── core/
│   │   ├── decision_engine/ # Risk scoring, correlation, confidence
│   │   ├── mitre/           # Technique mapping and coverage
│   │   └── parsers.py       # Source-specific event parsers
│   ├── enrichment/          # VirusTotal, AbuseIPDB, IOC extraction
│   ├── models/              # SQLAlchemy models (Alert, User, AuditLog, etc.)
│   ├── security/            # Auth, RBAC, JWT, middleware, sanitization
│   └── config.py            # Pydantic settings (reads from .env)
├── frontend/
│   ├── src/
│   │   ├── api/             # Typed API client functions
│   │   ├── components/      # Reusable UI components (charts, tables, badges)
│   │   ├── hooks/           # React Query hooks (useAlerts, useDashboard, etc.)
│   │   ├── pages/           # Page components
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Alerts.tsx
│   │   │   ├── AlertDetail.tsx
│   │   │   ├── Incidents.tsx
│   │   │   ├── MitreCoverage.tsx
│   │   │   ├── Sources.tsx
│   │   │   ├── Settings.tsx
│   │   │   ├── UserManagement.tsx
│   │   │   └── SetupWizard.tsx
│   │   └── security/        # AuthContext, ProtectedRoute, session handling
│   └── templates/           # Jinja2 templates (server-rendered fallback)
├── tests/                   # Pytest suite (unit, integration, security)
├── scripts/
│   ├── create_admin.py      # CLI admin user creation
│   ├── seed_data.py         # Load 15 realistic sample alerts
│   └── security_check.py    # Pre-commit security scan
├── docker/                  # Dockerfile, docker-compose, Prometheus, Grafana
├── alembic/                 # Database migrations
└── .env.example             # Template — copy to .env and fill in your values
```

---

## Security Design

KESTREL is built with secure defaults appropriate for SOC environments:

| Control | Implementation |
|---------|---------------|
| Password hashing | argon2id via `argon2-cffi` (OWASP recommended over bcrypt) |
| JWT signing | RS256 asymmetric — private key never leaves the server |
| Session management | httpOnly refresh cookie + short-lived access token (15 min) |
| Account lockout | Progressive delay + lockout after 5 failed attempts |
| RBAC | Fine-grained permissions enforced on every route via FastAPI dependency |
| Input sanitization | XSS filtering, JSON depth limits, path traversal protection |
| Audit logging | Every analyst action written to `AuditLog` table |
| Security headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options |
| Rate limiting | Per-IP limits on auth and ingest endpoints |
| Secret storage | All credentials in `.env` only — never in code or repository |

**For production:**
- Terminate TLS at a reverse proxy (nginx, Caddy, or cloud load balancer)
- Set `ENVIRONMENT=production` in `.env`
- Switch to PostgreSQL with SSL (`DATABASE_URL=postgresql+asyncpg://...`)
- Store secrets in a proper secret manager (Azure Key Vault, AWS Secrets Manager)
- Set `DEBUG=false`

---

## Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Yes | Random secret for signing (min 32 chars) |
| `DATABASE_URL` | Yes | SQLite or PostgreSQL connection string |
| `AI_PROVIDER` | No | `openai` / `anthropic` / `azure` (default: openai) |
| `OPENAI_API_KEY` | No | OpenAI API key |
| `ANTHROPIC_API_KEY` | No | Anthropic API key |
| `AZURE_OPENAI_API_KEY` | No | Azure OpenAI key |
| `AZURE_OPENAI_ENDPOINT` | No | Azure OpenAI endpoint URL |
| `AZURE_TENANT_ID` | No | Azure AD tenant ID (Sentinel) |
| `AZURE_CLIENT_ID` | No | Azure app client ID (Sentinel) |
| `AZURE_CLIENT_SECRET` | No | Azure app secret (Sentinel) |
| `LOGANALYTICS_WORKSPACE_ID` | No | Log Analytics workspace ID (Sentinel) |
| `AWS_ACCESS_KEY_ID` | No | AWS access key (GuardDuty) |
| `AWS_SECRET_ACCESS_KEY` | No | AWS secret key (GuardDuty) |
| `AWS_REGION` | No | AWS region (default: us-east-1) |
| `VIRUSTOTAL_API_KEY` | No | VirusTotal API key (enrichment) |
| `ABUSEIPDB_API_KEY` | No | AbuseIPDB API key (enrichment) |
| `SLACK_WEBHOOK_URL` | No | Slack incoming webhook (notifications) |
| `DEBUG` | No | `true` for development (default: false) |

All of these can be set through the Settings UI after first login — no need to edit `.env` manually.

---

## Built With

- [FastAPI](https://fastapi.tiangolo.com/) — async Python web framework
- [SQLAlchemy](https://www.sqlalchemy.org/) — async ORM
- [Alembic](https://alembic.sqlalchemy.org/) — database migrations
- [argon2-cffi](https://argon2-cffi.readthedocs.io/) — password hashing
- [python-jose](https://python-jose.readthedocs.io/) — JWT signing
- [React](https://react.dev/) — frontend framework
- [Vite](https://vitejs.dev/) — frontend build tool
- [TailwindCSS](https://tailwindcss.com/) — utility-first CSS
- [Recharts](https://recharts.org/) — charting library
- [TanStack Query](https://tanstack.com/query) — async state management
- [MITRE ATT&CK](https://attack.mitre.org/) — threat framework

---

## License

See `LICENSE` for details.

---

## Author

Built by [Sai Manikanta Teja Parwatha](https://www.linkedin.com/in/tejaparwatha/) demonstrating SOC operations, detection engineering, cloud security, and AI-assisted triage.

