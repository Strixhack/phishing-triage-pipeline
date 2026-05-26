"""
Mock Stub Server
Simulates VirusTotal, AbuseIPDB, MISP, and TheHive with
realistic response shapes. Runs as a separate service on port 9000.

Stubs use a deterministic seed from the IOC value so the same
IOC always gets the same (fake) score — useful for demo reproducibility.
"""
import hashlib
import random

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Phishing Triage — Mock Stubs", version="1.0.0")


def _seed_score(value: str, lo: int = 0, hi: int = 100) -> float:
    """Deterministic score based on IOC value hash."""
    digest = int(hashlib.md5(value.encode()).hexdigest(), 16)
    rng = random.Random(digest)
    return round(rng.uniform(lo, hi), 1)


def _is_suspicious_value(value: str) -> bool:
    """Simple heuristic — known-bad keywords trigger higher scores."""
    bad = ["malware", "phish", "evil", "hack", "trojan", "exploit", "ransom"]
    return any(b in value.lower() for b in bad)


# ── VirusTotal stub ────────────────────────────────────────────────────────────

class VTRequest(BaseModel):
    ioc: str
    type: str


@app.post("/mock/virustotal")
async def mock_virustotal(req: VTRequest):
    if _is_suspicious_value(req.ioc):
        malicious = int(_seed_score(req.ioc, 20, 70))
    else:
        malicious = int(_seed_score(req.ioc, 0, 8))

    total = 70
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": max(0, malicious // 3),
                    "undetected": total - malicious - malicious // 3,
                    "harmless": 2,
                    "timeout": 0,
                },
                "reputation": -malicious,
            }
        }
    }


# ── AbuseIPDB stub ─────────────────────────────────────────────────────────────

class AbuseIPDBRequest(BaseModel):
    ip: str


@app.post("/mock/abuseipdb")
async def mock_abuseipdb(req: AbuseIPDBRequest):
    if _is_suspicious_value(req.ip):
        score = _seed_score(req.ip, 60, 100)
    else:
        score = _seed_score(req.ip, 0, 20)

    return {
        "data": {
            "ipAddress": req.ip,
            "abuseConfidenceScore": score,
            "countryCode": "DE",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Mock ISP GmbH",
            "domain": "mock-isp.example",
            "totalReports": int(score / 5),
            "numDistinctUsers": max(1, int(score / 10)),
            "lastReportedAt": "2024-10-15T12:00:00+00:00",
        }
    }


# ── MISP stub ─────────────────────────────────────────────────────────────────

class MISPRequest(BaseModel):
    value: str


@app.post("/mock/misp")
async def mock_misp(req: MISPRequest):
    if _is_suspicious_value(req.value):
        hits = int(_seed_score(req.value, 1, 5))
    else:
        hits = 0

    attrs = [
        {
            "id": str(i + 1),
            "event_id": str(1000 + i),
            "type": "url",
            "value": req.value,
            "to_ids": True,
            "category": "Network activity",
            "timestamp": "1728000000",
        }
        for i in range(hits)
    ]
    return {"response": {"Attribute": attrs}}


# ── TheHive stub ───────────────────────────────────────────────────────────────

class TheHiveRequest(BaseModel):
    title: str
    description: str
    severity: int
    tlp: int
    tags: list[str]
    source: str
    sourceRef: str
    flag: bool = False


@app.post("/mock/thehive/case", status_code=201)
async def mock_thehive_case(req: TheHiveRequest):
    case_id = f"~{abs(hash(req.sourceRef)) % 900000 + 100000}"
    return {
        "id": case_id,
        "_id": case_id,
        "title": req.title,
        "severity": req.severity,
        "status": "New",
        "tags": req.tags,
        "_type": "case",
    }


@app.get("/health")
async def health():
    return {"status": "ok", "service": "mock-stubs"}


# ── Cortex stub ───────────────────────────────────────────────────────────────

class CortexRequest(BaseModel):
    analyser: str
    ioc: str
    type: str


@app.post("/mock/cortex/analyse")
async def mock_cortex(req: CortexRequest):
    import uuid
    score = _seed_score(req.ioc, 0, 100)
    suspicious = _is_suspicious_value(req.ioc)

    level = "malicious" if suspicious and score > 60 else \
            "suspicious" if suspicious or score > 40 else \
            "safe" if score < 20 else "info"

    summaries = {
        "VirusTotal_GetReport": f"Detected by {int(score * 0.7)}/70 engines. Reputation score: {-int(score)}.",
        "URLhaus_2_0":          f"URL status: {'malware' if suspicious else 'online'}. Tags: {'phishing, malware' if suspicious else 'none'}.",
        "DomainTools_Iris":     f"Domain age: {int(_seed_score(req.ioc, 1, 1000))} days. Registrar: Mock Registrar Inc.",
        "Abuse_Finder":         f"Abuse contact: abuse@mock-isp.example. {'Reported {int(score/5)} times.' if suspicious else 'No reports.'}",
        "MalwareBazaar_1_0":    f"Hash {'found' if suspicious else 'not found'} in MalwareBazaar. {'Tags: trojan, downloader.' if suspicious else ''}",
    }

    return {
        "job_id": str(uuid.uuid4())[:8],
        "analyser": req.analyser,
        "level": level,
        "summary": summaries.get(req.analyser, f"{req.analyser} analysis complete."),
        "report": {
            "summary": {
                "taxonomies": [{"level": level, "namespace": req.analyser, "predicate": "Score", "value": f"{score:.0f}"}]
            }
        }
    }
