"""
Phishing Triage Pipeline — FastAPI Application
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import emails, cases, iocs, nis2, health, campaigns
from app.core.database import init_db
from app.core.config import settings

app = FastAPI(
    title="Phishing Triage API",
    description=(
        "Automated phishing email triage with NIS2-aligned case management, "
        "YARA scanning, MITRE ATT&CK mapping, campaign detection, and Cortex integration."
    ),
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router,     prefix="/api",            tags=["health"])
app.include_router(emails.router,     prefix="/api/emails",     tags=["emails"])
app.include_router(cases.router,      prefix="/api/cases",      tags=["cases"])
app.include_router(iocs.router,       prefix="/api/iocs",       tags=["iocs"])
app.include_router(nis2.router,       prefix="/api/nis2",       tags=["nis2"])
app.include_router(campaigns.router,  prefix="/api/campaigns",  tags=["campaigns"])


@app.on_event("startup")
async def startup():
    await init_db()
