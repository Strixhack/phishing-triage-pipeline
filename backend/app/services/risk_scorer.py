"""
Risk Scorer
Produces a 0â€“100 composite risk score for a case from:
  - IOC enrichment results (VT, AbuseIPDB, MISP)
  - Email auth failures (SPF/DKIM/DMARC)
  - Heuristics (reply-to mismatch, suspicious subject keywords)

Score bands:
  0â€“29   â†’ BENIGN
  30â€“59  â†’ SUSPICIOUS
  60â€“100 â†’ MALICIOUS
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

from app.services.email_parser import EmailParseResult


@dataclass
class IOCEnrichment:
    value: str
    ioc_type: str
    vt_score: Optional[float] = None      # 0â€“1 (detections / total engines)
    abuseipdb_score: Optional[float] = None  # 0â€“100
    misp_hits: int = 0


@dataclass
class ScoringResult:
    total: float
    breakdown: dict[str, float]
    verdict: str


# â”€â”€ Weights (must sum to 1.0) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_W_VT          = 0.35
_W_ABUSEIPDB   = 0.20
_W_MISP        = 0.20
_W_AUTH        = 0.15
_W_HEURISTICS  = 0.10

_SUSPICIOUS_SUBJECTS = [
    "urgent", "account suspended", "verify", "unusual sign",
    "limited time", "action required", "invoice", "payment",
    "password", "security alert", "compromised", "click here",
    "confirm your", "winner", "lottery", "free", "claim",
]


def score_case(
    parse_result: EmailParseResult,
    ioc_enrichments: list[IOCEnrichment],
) -> ScoringResult:

    # â”€â”€ IOC scores â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    vt_raw = _avg_ioc_score(
        [e.vt_score * 100 for e in ioc_enrichments if e.vt_score is not None]
    )
    abuse_raw = _avg_ioc_score(
        [e.abuseipdb_score for e in ioc_enrichments if e.abuseipdb_score is not None]
    )
    misp_raw = min(100.0, sum(e.misp_hits for e in ioc_enrichments) * 25.0)

    # â”€â”€ Auth score â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    auth_raw = _auth_score(parse_result.spf, parse_result.dkim, parse_result.dmarc)

    # â”€â”€ Heuristic score â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    heuristic_raw = _heuristic_score(parse_result)

    # â”€â”€ Weighted total â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    total = (
        vt_raw       * _W_VT
        + abuse_raw  * _W_ABUSEIPDB
        + misp_raw   * _W_MISP
        + auth_raw   * _W_AUTH
        + heuristic_raw * _W_HEURISTICS
    )
    total = round(min(100.0, total), 1)

    verdict = _to_verdict(total)

    return ScoringResult(
        total=total,
        breakdown={
            "virustotal":  round(vt_raw, 1),
            "abuseipdb":   round(abuse_raw, 1),
            "misp":        round(misp_raw, 1),
            "auth":        round(auth_raw, 1),
            "heuristics":  round(heuristic_raw, 1),
        },
        verdict=verdict,
    )


# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _avg_ioc_score(scores: list[float]) -> float:
    return sum(scores) / len(scores) if scores else 0.0


def _auth_score(spf: str, dkim: str, dmarc: str) -> float:
    score = 0.0
    fail_map = {"fail": 40.0, "softfail": 25.0, "none": 15.0, "permerror": 35.0}
    score += fail_map.get(spf, 0.0)
    score += fail_map.get(dkim, 0.0)
    score += fail_map.get(dmarc, 0.0)
    return min(100.0, score)


def _heuristic_score(result: EmailParseResult) -> float:
    score = 0.0
    subject_lower = result.subject.lower()

    # Suspicious keywords
    hits = sum(1 for kw in _SUSPICIOUS_SUBJECTS if kw in subject_lower)
    score += min(50.0, hits * 15.0)

    # Reply-to mismatch
    if result.reply_to and result.sender:
        sender_domain   = _domain_from_addr(result.sender)
        reply_to_domain = _domain_from_addr(result.reply_to)
        if sender_domain and reply_to_domain and sender_domain != reply_to_domain:
            score += 30.0

    # Suspicious attachment types
    dangerous_exts = {".exe", ".vbs", ".js", ".ps1", ".bat", ".cmd", ".scr", ".hta"}
    for att in result.attachments:
        fn = att.get("filename", "").lower()
        if any(fn.endswith(ext) for ext in dangerous_exts):
            score += 40.0
            break

    return min(100.0, score)


def _domain_from_addr(addr: str) -> str:
    import re
    m = re.search(r'@([\w.\-]+)', addr)
    return m.group(1).lower() if m else ""


def _to_verdict(score: float) -> str:
    if score >= 55:
        return "malicious"
    if score >= 30:
        return "suspicious"
    return "benign"
