# ShadowHound — AI-Powered Threat Hunting Agent

An agentic AI system for hypothesis-driven threat hunting. ShadowHound autonomously formulates threat hypotheses, plans and executes approved queries across your security data sources, aggregates evidence, and produces structured hunt reports for human analysts.

---

## Architecture

```
Analyst / Scheduler / Intel Alert
            ↓
   Hypothesis Engine (LLM)
            ↓
  Query Planner → Approval Gate → Query Executor
            ↓
   EDR | SIEM | Threat Intel | Playbooks
            ↓
  Evidence Aggregator + Confidence Scorer
            ↓
      Hunt Report (PDF / JSON / MD)
            ↓
      Analyst Dashboard
```

**Stack:** Python 3.12 · FastAPI · Celery + Redis · PostgreSQL · Google Gemini · React 18

---

## Prerequisites

- Python 3.12+
- Node.js 20+
- Docker + Docker Compose
- Gemini API key

---

## Quick Start (Docker)

```bash
# 1. Clone and configure
git clone <repo>
cd shadowhound
cp .env.example .env
# Edit .env — at minimum set GEMINI_API_KEY

# 2. Start all services
docker compose up -d

# 3. Bootstrap (creates DB tables, admin user, Vault placeholders)
docker compose exec api python scripts/bootstrap.py

# 4. Open the dashboard
open http://localhost:3000
# Login: admin@shadowhound.local / Admin@ShadowHoundChange!
```

---

## Local Development Setup

```bash
# 1. Infrastructure only
docker compose up -d postgres redis vault weaviate

# 2. Python environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 3. Environment
cp .env.example .env
# Edit .env

# 4. Bootstrap
python scripts/bootstrap.py --skip-migrations

# 5. Start API
uvicorn main:app --reload --port 8000

# 6. Start Celery worker (new terminal)
celery -A agent.tasks.celery_app worker --loglevel=info

# 7. Start dashboard (new terminal)
cd dashboard
npm install
npm run dev
# Dashboard: http://localhost:3000
# API docs:  http://localhost:8000/docs
```

---

## Project Structure

```
shadowhound/
├── main.py                        # FastAPI app entry point
├── requirements.txt
├── docker-compose.yml
├── alembic.ini
├── pytest.ini
├── .env.example                   # Environment template with security guidance
│
├── config/
│   ├── settings.py                # Pydantic settings (from env)
│   └── vault.py                   # HashiCorp Vault client
│
├── db/
│   ├── models.py                  # SQLAlchemy ORM models (8 tables)
│   ├── session.py                 # DB engine + session factory
│   └── migrations/
│       ├── env.py                 # Alembic migration env
│       ├── script.py.mako         # Migration template
│       └── versions/
│           └── 001_initial_schema.py  # Initial schema migration
│
├── agent/
│   ├── hypothesis_engine.py       # LLM hypothesis generation
│   ├── query_planner.py           # LLM query planning + safety validation
│   ├── evidence_aggregator.py     # LLM evidence synthesis + confidence scoring
│   ├── orchestrator.py            # Main hunt loop (8-phase OODA)
│   ├── report_builder.py          # Hunt report generation (PDF/JSON/MD)
│   └── tasks.py                   # Celery async tasks
│
├── api/
│   ├── auth.py                    # JWT auth + RBAC
│   ├── schemas.py                 # Pydantic request/response schemas
│   ├── audit.py                   # Immutable audit logging
│   └── routers/
│       ├── hunts.py               # Hunt session CRUD + lifecycle
│       ├── queries.py             # Query approval gate endpoints
│       └── auth_users.py          # Auth endpoints + user management
│
├── integrations/
│   ├── dispatcher.py              # Routes queries to correct integration
│   ├── edr/
│   │   ├── crowdstrike_client.py
│   │   ├── sentinelone_client.py
│   │   └── defender_client.py
│   ├── siem/
│   │   ├── splunk_client.py
│   │   ├── sentinel_client.py
│   │   └── elastic_client.py
│   ├── threat_intel/
│   │   ├── misp_client.py
│   │   ├── virustotal_client.py
│   │   └── opencti_client.py
│   └── playbooks/
│       └── playbook_client.py
│
├── data/
│   └── playbooks/                 # YAML/JSON hunting playbooks (5 total)
│       ├── lateral_movement_wmi.yml
│       ├── credential_access_dumping.yml
│       ├── ransomware_execution.yml
│       ├── phishing_initial_access.yml
│       └── persistence_registry_run_keys.yml
│
├── reports/
│   └── output/                    # Generated hunt reports
│
├── dashboard/
│   ├── index.html                 # Vite entry point
│   ├── src/
│   │   ├── main.jsx               # React 18 root render
│   │   ├── index.css              # Global styles + CSS custom properties
│   │   └── App.jsx                # React SPA (full dashboard)
│   ├── package.json
│   └── vite.config.js
│
├── tests/
│   ├── test_ps281.py              # Unit test suite (37 tests)
│   └── test_integration.py        # Integration test suite (API workflows)
│
├── scripts/
│   ├── bootstrap.py               # DB + admin user + Vault seed
│   └── create_init_files.py
│
└── infra/
    ├── Dockerfile.api
    ├── Dockerfile.dashboard
    ├── nginx.conf
    ├── otel-collector-config.yaml  # OpenTelemetry Collector config
    └── grafana/
        ├── datasources/
        │   └── datasources.yml     # Auto-provision Loki datasource
        └── dashboards/
            ├── dashboard.yml       # Dashboard provisioner
            └── shadowhound.json    # ShadowHound overview dashboard
```

---

## Configuration

All config via environment variables (`.env` file). Key settings:

| Variable | Description | Required |
|---|---|---|
| `GEMINI_API_KEY` | Your Google Gemini API key | ✅ |
| `DATABASE_URL` | PostgreSQL connection string | ✅ |
| `REDIS_URL` | Redis connection string | ✅ |
| `JWT_SECRET_KEY` | Secret for JWT signing (generate with `openssl rand -hex 32`) | ✅ |
| `CROWDSTRIKE_CLIENT_ID` | CrowdStrike API OAuth2 client ID | Optional |
| `SPLUNK_TOKEN` | Splunk API token | Optional |
| `MISP_API_KEY` | MISP API key | Optional |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | Optional |

Configure only the integrations you have access to. ShadowHound gracefully skips unconfigured sources.

---

## Adding Integrations

### Step 1 — Add credentials to Vault

```bash
# Using the Vault CLI
vault kv put shadowhound/integrations/crowdstrike \
  client_id=your_id \
  client_secret=your_secret

# Or update .env directly for development
echo "CROWDSTRIKE_CLIENT_ID=your_id" >> .env
echo "CROWDSTRIKE_CLIENT_SECRET=your_secret" >> .env
```

### Step 2 — Restart the API and worker
```bash
docker compose restart api worker
```

The system auto-detects configured integrations on startup and includes them in hypothesis generation.

---

## Adding Hunt Playbooks

Create YAML files in `data/playbooks/`. See `lateral_movement_wmi.yml` for the full schema.

Minimum required fields:
```yaml
title: Your Playbook Title
description: What this playbook hunts for
tactics: [Lateral Movement]
tags: [attack.t1047, windows]
mitre_attack:
  techniques:
    - id: T1047
      name: Windows Management Instrumentation
query_templates:
  splunk: |
    search index=* ...
```

---

## API Reference

Full interactive docs at `http://localhost:8000/docs`

### Key endpoints

```
POST   /api/v1/auth/login                         Login, get tokens
GET    /api/v1/auth/me                             Current user

POST   /api/v1/hunts                              Create + start a hunt
GET    /api/v1/hunts                              List all hunts
GET    /api/v1/hunts/{id}                         Hunt detail (hypotheses, queries, evidence)
POST   /api/v1/hunts/{id}/cancel                  Cancel a running hunt
GET    /api/v1/hunts/{id}/report                  Get hunt report
GET    /api/v1/hunts/{id}/report/download?format=pdf  Download report

GET    /api/v1/hunts/{id}/queries                 List queries for a hunt
POST   /api/v1/hunts/{id}/queries/{qid}/approve   Approve a query
POST   /api/v1/hunts/{id}/queries/{qid}/reject    Reject a query (reason required)
POST   /api/v1/hunts/{id}/queries/bulk-approve    Approve all pending queries at once

POST   /api/v1/users                              Create user (admin only)
GET    /api/v1/users                              List users (admin only)
GET    /api/v1/users/audit-log                    Full audit log (admin only)
```

### Hunt lifecycle

```
CREATE hunt → PENDING
  → HYPOTHESIZING (LLM generates ranked hypotheses)
  → PLANNING (LLM drafts platform-specific queries)
  → AWAITING_APPROVAL (analyst reviews + approves queries)
  → EXECUTING (approved queries dispatched to data sources)
  → ANALYZING (LLM evaluates evidence, scores confidence)
  → [loop back to PLANNING if below threshold]
  → REPORTING (hunt report generated)
  → COMPLETED
```

---

## User Roles

| Role | Permissions |
|---|---|
| `analyst` | Create hunts, view own hunts, view reports |
| `approver` | All analyst permissions + approve/reject queries across all hunts |
| `admin` | All permissions + user management + audit log |

---

## Running Tests

```bash
# All tests
pytest tests/ -v

# Specific class
pytest tests/ -v -k "TestAuth"
pytest tests/ -v -k "TestQueryPlanner"

# With coverage
pytest tests/ --cov=. --cov-report=html
open htmlcov/index.html
```

---

## Production Deployment

### Security Checklist

1. **Generate secrets** — replace all placeholder keys in `.env`:
   ```bash
   # App secret
   python -c "import secrets; print(secrets.token_hex(32))"
   # JWT secret
   openssl rand -hex 32
   ```
2. **Set `APP_ENV=production`** — disables debug mode and auto-create-all
3. **Use PostgreSQL** — change `DATABASE_URL` from SQLite to PostgreSQL
4. **Run Alembic migrations** — `alembic upgrade head`
5. **Configure Vault** — replace `VAULT_TOKEN=root` with a real policy-scoped token
6. **Set a real Gemini API key** — required for the AI agent to function
7. **Enable HTTPS** — configure TLS termination in nginx or a reverse proxy
8. **Restrict CORS** — update `allow_origins` in `main.py` to your domain

### Docker Production Deploy

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env with production values

# 2. Start all services
docker compose up -d

# 3. Run migrations
docker compose exec api alembic upgrade head

# 4. Bootstrap admin user
docker compose exec api python scripts/bootstrap.py \
  --admin-email admin@yourcompany.com \
  --admin-password YourSecurePassword!
```

---

## Security Notes

- All queries pass through a **safety validation layer** before being presented for approval — blocked patterns include `DELETE`, `DROP`, `TRUNCATE`, `EXEC`, SPL `outputlookup`, and KQL `invoke`.
- No query touches a production system without **explicit human approval**.
- All actions are written to an **immutable audit log** with user identity, timestamp, and payload hash.
- All credentials stored in **HashiCorp Vault** — never in code or environment files in production.
- Raw security event data is **never persisted** beyond what is summarised in the final hunt report.
- LLM prompts use **structured message fields** for external data to prevent prompt injection.

---

## Monitoring

| Service | URL | Credentials |
|---|---|---|
| API Docs | http://localhost:8000/docs | — |
| Dashboard | http://localhost:3000 | admin@shadowhound.local / Admin@ShadowHoundChange! |
| Celery Flower | http://localhost:5555 | — |
| Grafana | http://localhost:3001 | admin / admin |
| Vault | http://localhost:8200 | Token: root |

---

## License

Internal use only. CONFIDENTIAL.
