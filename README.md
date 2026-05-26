# Phishing Triage Pipeline

Automated phishing email triage platform for SOC teams. Parses `.eml` files, enriches IOCs against VirusTotal, AbuseIPDB, and MISP, scores risk, auto-creates TheHive cases, and provides a React analyst dashboard with NIS2-aligned compliance timers.

## Stack

| Layer | Technology |
|-------|-----------|
| Backend API | Python 3.12 Â· FastAPI Â· SQLAlchemy (async) Â· SQLite |
| Enrichment | VirusTotal Â· AbuseIPDB Â· MISP (mock stubs included) |
| Case management | TheHive (mock stub included) |
| Frontend | React 18 Â· Recharts Â· React Router |
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
    â”‚
    â–¼
email_parser.py          â† extracts headers, IOCs, SPF/DKIM/DMARC
    â”‚
    â–¼
enrichment.py            â† queries VT / AbuseIPDB / MISP (or stubs)
    â”‚
    â–¼
risk_scorer.py           â† weighted composite score (0â€“100)
    â”‚
    â”œâ”€â”€ SQLite DB         â† cases, IOCs, audit log
    â”œâ”€â”€ TheHive stub      â† enriched case creation
    â””â”€â”€ NIS2 service      â† 24h/72h timer computation
    â”‚
    â–¼
FastAPI REST API
    â”‚
    â–¼
React Dashboard          â† triage queue, IOC detail, analyst actions, NIS2 view
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
| AbuseIPDB | 20% | confidence score 0â€“100 |
| MISP | 20% | 25 points per hit, capped at 100 |
| Auth (SPF/DKIM/DMARC) | 15% | fail = 40pts each |
| Heuristics | 10% | subject keywords, reply-to mismatch, dangerous attachments |

**Verdict bands:** 0â€“29 Benign Â· 30â€“59 Suspicious Â· 60â€“100 Malicious

## Running Tests

```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v
```

## NIS2 Compliance

Cases with verdict `MALICIOUS` or risk score â‰¥ 60 are flagged as significant incidents under NIS2 Article 23. The platform automatically:
- Sets a 24h early warning deadline
- Sets a 72h incident notification deadline
- Highlights overdue cases in the NIS2 dashboard
- Records notification status in the immutable audit log

See [docs/SOC_L1_RUNBOOK.md](docs/SOC_L1_RUNBOOK.md) for the full analyst procedure.

## Project Structure

```
phishing-triage/
â”œâ”€â”€ backend/
â”‚   â”œâ”€â”€ app/
â”‚   â”‚   â”œâ”€â”€ api/          â† FastAPI route handlers
â”‚   â”‚   â”œâ”€â”€ core/         â† config, database
â”‚   â”‚   â”œâ”€â”€ models/       â† SQLAlchemy models
â”‚   â”‚   â”œâ”€â”€ services/     â† parser, enrichment, scorer, NIS2, TheHive
â”‚   â”‚   â””â”€â”€ stubs/        â† mock API server
â”‚   â””â”€â”€ tests/
â”œâ”€â”€ frontend/
â”‚   â””â”€â”€ src/
â”‚       â”œâ”€â”€ api/          â† API client
â”‚       â””â”€â”€ pages/        â† Dashboard, CaseList, CaseDetail, Upload, NIS2
â”œâ”€â”€ docs/
â”‚   â””â”€â”€ SOC_L1_RUNBOOK.md
â””â”€â”€ docker-compose.yml
```
