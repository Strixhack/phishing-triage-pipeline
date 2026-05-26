"""
Cortex Analyser Integration
Submits IOCs to Cortex analysers and retrieves enriched reports.
Cortex is TheHive's companion platform for automated enrichment.

Supported analysers (mock):
  - VirusTotal_GetReport  — full VT report for URL/domain/hash
  - Abuse_Finder         — finds abuse contacts for IP/domain
  - DomainTools_Iris     — WHOIS and domain intelligence
  - URLhaus_2_0          — URLhaus malware URL database
  - MalwareBazaar_1_0    — MalwareBazaar hash lookup
"""
from __future__ import annotations
import httpx
import asyncio
from dataclasses import dataclass, field

from app.core.config import settings


@dataclass
class CortexJob:
    job_id: str
    analyser: str
    ioc_value: str
    ioc_type: str
    status: str              # Waiting / InProgress / Success / Failure
    report: dict = field(default_factory=dict)
    summary: str = ""
    level: str = "info"      # info / safe / suspicious / malicious


@dataclass
class CortexResult:
    ioc_value: str
    ioc_type: str
    jobs: list[CortexJob] = field(default_factory=list)
    highest_level: str = "info"


# Analyser routing — which analysers run for which IOC types
_ANALYSER_ROUTING = {
    "url":    ["VirusTotal_GetReport", "URLhaus_2_0"],
    "domain": ["VirusTotal_GetReport", "DomainTools_Iris", "Abuse_Finder"],
    "ip":     ["Abuse_Finder", "VirusTotal_GetReport"],
    "hash":   ["VirusTotal_GetReport", "MalwareBazaar_1_0"],
    "email":  ["Abuse_Finder"],
}

_LEVEL_ORDER = ["info", "safe", "suspicious", "malicious"]


async def run_cortex_analysers(
    ioc_value: str,
    ioc_type: str,
) -> CortexResult:
    """
    Submits IOC to relevant Cortex analysers and returns aggregated result.
    Uses mock endpoint when USE_MOCK_STUBS=true.
    """
    result = CortexResult(ioc_value=ioc_value, ioc_type=ioc_type)
    analysers = _ANALYSER_ROUTING.get(ioc_type, [])

    if settings.use_mock_stubs:
        jobs = await _run_mock_analysers(ioc_value, ioc_type, analysers)
    else:
        jobs = await _run_live_analysers(ioc_value, ioc_type, analysers)

    result.jobs = jobs
    if jobs:
        result.highest_level = max(
            (j.level for j in jobs),
            key=lambda l: _LEVEL_ORDER.index(l) if l in _LEVEL_ORDER else 0
        )

    return result


async def _run_mock_analysers(
    ioc_value: str,
    ioc_type: str,
    analysers: list[str],
) -> list[CortexJob]:
    """Calls the mock stub server for each analyser."""
    jobs = []
    async with httpx.AsyncClient(timeout=10.0) as client:
        for analyser in analysers:
            try:
                resp = await client.post(
                    f"{settings.mock_stub_base_url}/mock/cortex/analyse",
                    json={"analyser": analyser, "ioc": ioc_value, "type": ioc_type},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    jobs.append(CortexJob(
                        job_id=data.get("job_id", f"mock-{analyser}"),
                        analyser=analyser,
                        ioc_value=ioc_value,
                        ioc_type=ioc_type,
                        status="Success",
                        report=data.get("report", {}),
                        summary=data.get("summary", ""),
                        level=data.get("level", "info"),
                    ))
            except Exception:
                pass
    return jobs


async def _run_live_analysers(
    ioc_value: str,
    ioc_type: str,
    analysers: list[str],
) -> list[CortexJob]:
    """
    Submits to real Cortex API.
    Cortex endpoint: POST /api/analyzer/{analyser_id}/run
    """
    if not settings.cortex_url or not settings.cortex_api_key:
        return []

    jobs = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        headers = {"Authorization": f"Bearer {settings.cortex_api_key}"}
        for analyser in analysers:
            try:
                # Submit job
                submit_resp = await client.post(
                    f"{settings.cortex_url}/api/analyzer/{analyser}/run",
                    json={
                        "data": ioc_value,
                        "dataType": ioc_type,
                        "tlp": 2,
                    },
                    headers=headers,
                )
                if submit_resp.status_code not in (200, 201):
                    continue

                job_data = submit_resp.json()
                job_id = job_data.get("id")

                # Poll for completion (max 30s)
                for _ in range(10):
                    await asyncio.sleep(3)
                    status_resp = await client.get(
                        f"{settings.cortex_url}/api/job/{job_id}",
                        headers=headers,
                    )
                    if status_resp.status_code != 200:
                        break
                    status_data = status_resp.json()
                    if status_data.get("status") in ("Success", "Failure"):
                        report = status_data.get("report", {})
                        summary = report.get("summary", {})
                        level = _extract_level(report)
                        jobs.append(CortexJob(
                            job_id=job_id,
                            analyser=analyser,
                            ioc_value=ioc_value,
                            ioc_type=ioc_type,
                            status=status_data["status"],
                            report=report,
                            summary=str(summary),
                            level=level,
                        ))
                        break
            except Exception:
                pass
    return jobs


def _extract_level(report: dict) -> str:
    """Extract highest level from Cortex report taxonomies."""
    taxonomies = report.get("summary", {}).get("taxonomies", [])
    if not taxonomies:
        return "info"
    levels = [t.get("level", "info") for t in taxonomies]
    return max(levels, key=lambda l: _LEVEL_ORDER.index(l) if l in _LEVEL_ORDER else 0)
