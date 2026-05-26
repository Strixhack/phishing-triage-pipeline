from __future__ import annotations
import httpx
from app.core.config import settings
from app.services.risk_scorer import IOCEnrichment
async def enrich_iocs(ioc_values: list[tuple[str, str]]) -> list[IOCEnrichment]:
    results = []
    async with httpx.AsyncClient(timeout=15.0) as client:
        for value, ioc_type in ioc_values:
            enrichment = IOCEnrichment(value=value, ioc_type=ioc_type)
            if ioc_type in ("url", "domain", "hash"):
                enrichment.vt_score = await _query_vt(client, value, ioc_type)
            if ioc_type == "ip":
                enrichment.abuseipdb_score = await _query_abuseipdb(client, value)
            enrichment.misp_hits = await _query_misp(client, value)
            results.append(enrichment)
    return results
async def _query_vt(client: httpx.AsyncClient, value: str, ioc_type: str) -> float | None:
    try:
        if settings.use_mock_stubs:
            resp = await client.post(
                f"{settings.mock_stub_base_url}/mock/virustotal",
                json={"ioc": value, "type": ioc_type}
            )
        else:
            import base64
            if ioc_type == "url":
                url_id = base64.urlsafe_b64encode(value.encode()).rstrip(b"=").decode()
                url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            elif ioc_type == "domain":
                url = f"https://www.virustotal.com/api/v3/domains/{value}"
            else:
                url = f"https://www.virustotal.com/api/v3/files/{value}"
            resp = await client.get(url, headers={"x-apikey": settings.vt_api_key})
        if resp.status_code != 200:
            return None
        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) or 1
        return malicious / total
    except Exception:
        return None
async def _query_abuseipdb(client: httpx.AsyncClient, ip: str) -> float | None:
    try:
        if settings.use_mock_stubs:
            resp = await client.post(
                f"{settings.mock_stub_base_url}/mock/abuseipdb",
                json={"ip": ip}
            )
        else:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            )
        if resp.status_code != 200:
            return None
        return resp.json().get("data", {}).get("abuseConfidenceScore")
    except Exception:
        return None
async def _query_misp(client: httpx.AsyncClient, value: str) -> int:
    try:
        if settings.use_mock_stubs:
            resp = await client.post(
                f"{settings.mock_stub_base_url}/mock/misp",
                json={"value": value}
            )
        else:
            if settings.misp_url == "MOCK":
                return 0
            resp = await client.post(
                f"{settings.misp_url}/attributes/restSearch",
                json={"value": value, "returnFormat": "json"},
                headers={"Authorization": settings.misp_api_key, "Accept": "application/json"},
            )
        if resp.status_code != 200:
            return 0
        return len(resp.json().get("response", {}).get("Attribute", []))
    except Exception:
        return 0
