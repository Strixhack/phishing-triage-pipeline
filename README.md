# Phishing Triage Pipeline

Automated phishing email triage platform for SOC teams. Parses `.eml` files, enriches IOCs against VirusTotal, AbuseIPDB, and MISP, scores risk, auto-creates TheHive cases, and provides a React analyst dashboard with NIS2-aligned compliance timers.

## Stack

| Layer | Technology |
|-------|-----------|
| Backend API | Python 3.12 · FastAPI · SQLAlchemy (async) · SQLite |
| Enrichment | VirusTotal · AbuseIPDB · MISP (mock stubs included) |
| Case management | TheHive (mock stub included) |
| Frontend | React 18 · Recharts · React Router |
| Infra | Docker Compose |
| Compliance | NIS2 Article 23 (24h/72h timers) |

## Quick Start

```bash
git clone <repo>
cd phishing-triage
cp .env.example .env
docker compose up --build
```

Then open:
- **Dashboard**: http://localhost:3000
- **API docs**: http://localhost:8000/api/docs
- **Mock stubs**: http://localhost:9000/docs

Upload any `.eml` file on the Upload page. The pipeline will parse, enrich, score, and create a TheHive case automatically.

## Architecture

```
.eml file
    │
    ▼
email_parser.py          ← extracts headers, IOCs, SPF/DKIM/DMARC
    │
    ▼
enrichment.py            ← queries VT / AbuseIPDB / MISP (or stubs)
    │
    ▼
risk_scorer.py           ← weighted composite score (0–100)
    │
    ├── SQLite DB         ← cases, IOCs, audit log
    ├── TheHive stub      ← enriched case creation
    └── NIS2 service      ← 24h/72h timer computation
    │
    ▼
FastAPI REST API
    │
    ▼
React Dashboard          ← triage queue, IOC detail, analyst actions, NIS2 view
```

## Switching to Real APIs

Set `USE_MOCK_STUBS=false` in `.env` and fill in your API keys:

```env
USE_MOCK_STUBS=false
VT_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
MISP_URL=https://your-misp.local
MISP_API_KEY=your_key
THEHIVE_URL=http://localhost:9001
THEHIVE_API_KEY=your_key
```

## Scoring Model

| Source | Weight | Notes |
|--------|--------|-------|
| VirusTotal | 35% | detections / total engines |
| AbuseIPDB | 20% | confidence score 0–100 |
| MISP | 20% | 25 points per hit, capped at 100 |
| Auth (SPF/DKIM/DMARC) | 15% | fail = 40pts each |
| Heuristics | 10% | subject keywords, reply-to mismatch, dangerous attachments |

**Verdict bands:** 0–29 Benign · 30–59 Suspicious · 60–100 Malicious

## Running Tests

```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v
```

## NIS2 Compliance

Cases with verdict `MALICIOUS` or risk score ≥ 60 are flagged as significant incidents under NIS2 Article 23. The platform automatically:
- Sets a 24h early warning deadline
- Sets a 72h incident notification deadline
- Highlights overdue cases in the NIS2 dashboard
- Records notification status in the immutable audit log

See [docs/SOC_L1_RUNBOOK.md](docs/SOC_L1_RUNBOOK.md) for the full analyst procedure.

## Project Structure

```
phishing-triage/
├── backend/
│   ├── app/
│   │   ├── api/          ← FastAPI route handlers
│   │   ├── core/         ← config, database
│   │   ├── models/       ← SQLAlchemy models
│   │   ├── services/     ← parser, enrichment, scorer, NIS2, TheHive
│   │   └── stubs/        ← mock API server
│   └── tests/
├── frontend/
│   └── src/
│       ├── api/          ← API client
│       └── pages/        ← Dashboard, CaseList, CaseDetail, Upload, NIS2
├── docs/
│   └── SOC_L1_RUNBOOK.md
└── docker-compose.yml
```
