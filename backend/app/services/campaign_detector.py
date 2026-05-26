"""
Campaign Detection Service
Clusters similar phishing cases into campaigns using:
  - Sender domain similarity
  - Subject template matching (after stripping variables)
  - URL domain overlap
  - IOC overlap score

A campaign is a group of 2+ cases likely sent by the same threat actor.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CampaignMatch:
    campaign_id: str
    case_ids: list[int]
    similarity_score: float      # 0â€“1
    shared_indicators: list[str] # what they have in common
    first_seen: datetime
    last_seen: datetime
    verdict: str                 # highest verdict in cluster


@dataclass
class CampaignCandidate:
    case_id: int
    sender_domain: str
    subject_template: str
    url_domains: list[str]
    verdict: str
    detected_at: datetime


# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_VAR_PATTERNS = [
    r'\b[A-Z0-9]{6,}\b',           # reference numbers / tokens
    r'\b\d{4,}\b',                  # long numbers (invoice IDs etc)
    r'\b[a-f0-9]{8,}\b',            # hex tokens
    r'\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\w*\s+\d{4}\b',
    r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b',  # dates
    r'#\w+',                        # hashtag-style refs
]

def _normalise_subject(subject: str) -> str:
    """Strip variable parts from subject to get template."""
    s = subject.lower().strip()
    for pat in _VAR_PATTERNS:
        s = re.sub(pat, "X", s, flags=re.IGNORECASE)
    s = re.sub(r'\s+', ' ', s).strip()
    return s


def _sender_domain(sender: str) -> str:
    m = re.search(r'@([\w.\-]+)', sender or "")
    return m.group(1).lower() if m else ""


def _domain_similarity(d1: str, d2: str) -> float:
    """Returns 1.0 if same domain, 0.5 if same TLD+1, 0.0 otherwise."""
    if not d1 or not d2:
        return 0.0
    if d1 == d2:
        return 1.0
    parts1 = d1.split(".")
    parts2 = d2.split(".")
    if len(parts1) >= 2 and len(parts2) >= 2:
        if parts1[-2:] == parts2[-2:]:
            return 0.5
    return 0.0


def _subject_similarity(s1: str, s2: str) -> float:
    """Simple token overlap similarity."""
    if not s1 or not s2:
        return 0.0
    t1 = set(s1.split())
    t2 = set(s2.split())
    if not t1 or not t2:
        return 0.0
    intersection = t1 & t2
    union = t1 | t2
    return len(intersection) / len(union)


def _url_domain_overlap(domains1: list[str], domains2: list[str]) -> float:
    """Returns fraction of shared URL domains."""
    if not domains1 or not domains2:
        return 0.0
    s1 = set(domains1)
    s2 = set(domains2)
    shared = s1 & s2
    if not shared:
        return 0.0
    return len(shared) / max(len(s1), len(s2))


def compute_case_similarity(c1: CampaignCandidate, c2: CampaignCandidate) -> tuple[float, list[str]]:
    """
    Returns (similarity_score 0â€“1, list of shared indicators).
    Score >= 0.4 â†’ likely same campaign.
    """
    score = 0.0
    shared = []

    # Sender domain (weight 0.35)
    d_sim = _domain_similarity(c1.sender_domain, c2.sender_domain)
    if d_sim > 0:
        score += d_sim * 0.35
        shared.append(f"Sender domain: {c1.sender_domain} ~ {c2.sender_domain}")

    # Subject template (weight 0.35)
    s_sim = _subject_similarity(c1.subject_template, c2.subject_template)
    if s_sim > 0.3:
        score += s_sim * 0.35
        shared.append(f"Subject template similarity: {s_sim:.0%}")

    # URL domain overlap (weight 0.30)
    u_sim = _url_domain_overlap(c1.url_domains, c2.url_domains)
    if u_sim > 0:
        score += u_sim * 0.30
        overlapping = list(set(c1.url_domains) & set(c2.url_domains))
        shared.append(f"Shared URL domains: {', '.join(overlapping[:3])}")

    return round(score, 3), shared


def detect_campaigns(cases: list[dict]) -> list[CampaignMatch]:
    """
    Input: list of case dicts with keys:
        id, sender, subject, url_domains (list), verdict, detected_at (datetime)
    Output: list of CampaignMatch grouped by similarity.
    """
    if len(cases) < 2:
        return []

    candidates = [
        CampaignCandidate(
            case_id=c["id"],
            sender_domain=_sender_domain(c.get("sender", "")),
            subject_template=_normalise_subject(c.get("subject", "")),
            url_domains=c.get("url_domains", []),
            verdict=c.get("verdict", "pending"),
            detected_at=c.get("detected_at", datetime.utcnow()),
        )
        for c in cases
    ]

    # Build similarity matrix
    THRESHOLD = 0.12
    clusters: list[set[int]] = []

    for i, c1 in enumerate(candidates):
        for j, c2 in enumerate(candidates):
            if i >= j:
                continue
            sim, shared = compute_case_similarity(c1, c2)
            if sim >= THRESHOLD:
                # Find or create cluster
                merged = False
                for cluster in clusters:
                    if c1.case_id in cluster or c2.case_id in cluster:
                        cluster.add(c1.case_id)
                        cluster.add(c2.case_id)
                        merged = True
                        break
                if not merged:
                    clusters.append({c1.case_id, c2.case_id})

    # Build CampaignMatch objects
    results = []
    verdict_order = {"malicious": 3, "suspicious": 2, "benign": 1, "pending": 0}

    for idx, cluster in enumerate(clusters):
        cluster_candidates = [c for c in candidates if c.case_id in cluster]
        cluster_cases = [c for c in cases if c["id"] in cluster]

        # Aggregate similarity and shared indicators
        total_sim = 0.0
        all_shared: list[str] = []
        pair_count = 0
        for i, c1 in enumerate(cluster_candidates):
            for j, c2 in enumerate(cluster_candidates):
                if i >= j:
                    continue
                sim, shared = compute_case_similarity(c1, c2)
                total_sim += sim
                all_shared.extend(shared)
                pair_count += 1

        avg_sim = total_sim / pair_count if pair_count > 0 else 0.0
        unique_shared = list(dict.fromkeys(all_shared))[:6]

        dates = [c.detected_at for c in cluster_candidates]
        verdicts = [c.verdict for c in cluster_candidates]
        top_verdict = max(verdicts, key=lambda v: verdict_order.get(v, 0))

        results.append(CampaignMatch(
            campaign_id=f"CAMP-{idx + 1:04d}",
            case_ids=sorted(cluster),
            similarity_score=round(avg_sim, 3),
            shared_indicators=unique_shared,
            first_seen=min(dates),
            last_seen=max(dates),
            verdict=top_verdict,
        ))

    return sorted(results, key=lambda c: c.similarity_score, reverse=True)
