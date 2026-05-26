"""
MITRE ATT&CK Mapping Service
Maps IOC types, email behaviours, and YARA matches to ATT&CK techniques.
Uses a static lookup table — no external API needed.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class ATTACKTechnique:
    technique_id: str      # e.g. T1566.002
    name: str              # e.g. Spearphishing Link
    tactic: str            # e.g. Initial Access
    description: str
    confidence: str        # high / medium / low
    source: str            # what triggered this mapping


# ── Static mapping table ──────────────────────────────────────────────────────

# Triggered by IOC type + enrichment
_IOC_TECHNIQUE_MAP: dict[str, list[dict]] = {
    "url": [
        {
            "technique_id": "T1566.002",
            "name": "Phishing: Spearphishing Link",
            "tactic": "Initial Access",
            "description": "Malicious URL embedded in email body to lure victim to attacker-controlled site.",
            "confidence": "high",
        },
        {
            "technique_id": "T1204.001",
            "name": "User Execution: Malicious Link",
            "tactic": "Execution",
            "description": "Relies on victim clicking a malicious link to execute attacker payload.",
            "confidence": "medium",
        },
    ],
    "ip": [
        {
            "technique_id": "T1071.001",
            "name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
            "description": "Attacker C2 communication using HTTP/HTTPS over IP.",
            "confidence": "medium",
        },
    ],
    "domain": [
        {
            "technique_id": "T1566.002",
            "name": "Phishing: Spearphishing Link",
            "tactic": "Initial Access",
            "description": "Attacker-controlled domain used to host phishing page or deliver payload.",
            "confidence": "high",
        },
        {
            "technique_id": "T1583.001",
            "name": "Acquire Infrastructure: Domains",
            "tactic": "Resource Development",
            "description": "Attacker registered or compromised this domain for use in attack campaign.",
            "confidence": "low",
        },
    ],
    "hash": [
        {
            "technique_id": "T1566.001",
            "name": "Phishing: Spearphishing Attachment",
            "tactic": "Initial Access",
            "description": "Malicious file hash detected — indicates weaponised attachment.",
            "confidence": "high",
        },
        {
            "technique_id": "T1204.002",
            "name": "User Execution: Malicious File",
            "tactic": "Execution",
            "description": "Victim execution of malicious attachment required to trigger payload.",
            "confidence": "high",
        },
    ],
}

# Triggered by auth failures
_AUTH_TECHNIQUE_MAP = {
    "spf_fail": {
        "technique_id": "T1078",
        "name": "Valid Accounts: Email Spoofing",
        "tactic": "Defense Evasion",
        "description": "SPF failure indicates sender domain spoofing — attacker impersonating legitimate sender.",
        "confidence": "high",
    },
    "dkim_fail": {
        "technique_id": "T1036.005",
        "name": "Masquerading: Match Legitimate Name",
        "tactic": "Defense Evasion",
        "description": "DKIM failure indicates email header manipulation or domain impersonation.",
        "confidence": "medium",
    },
    "dmarc_fail": {
        "technique_id": "T1078",
        "name": "Valid Accounts: Email Spoofing",
        "tactic": "Defense Evasion",
        "description": "DMARC failure confirms sender identity cannot be verified — likely spoofed.",
        "confidence": "high",
    },
}

# Triggered by heuristics
_HEURISTIC_TECHNIQUE_MAP = {
    "reply_to_mismatch": {
        "technique_id": "T1036",
        "name": "Masquerading",
        "tactic": "Defense Evasion",
        "description": "Reply-To domain differs from From domain — attacker redirecting replies to harvest credentials.",
        "confidence": "high",
    },
    "urgency_keywords": {
        "technique_id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "High-pressure urgency language used to bypass victim critical thinking.",
        "confidence": "medium",
    },
    "dangerous_attachment": {
        "technique_id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Dangerous attachment extension detected — potential malware delivery vector.",
        "confidence": "high",
    },
}

# Triggered by YARA rule name prefix
_YARA_TECHNIQUE_MAP = {
    "Ransomware":    ("T1486",     "Data Encrypted for Impact",           "Impact"),
    "Malware_Macro": ("T1566.001", "Phishing: Spearphishing Attachment",  "Initial Access"),
    "Malware_Drop":  ("T1105",     "Ingress Tool Transfer",               "Command and Control"),
    "BEC":           ("T1566.001", "Phishing: Spearphishing Attachment",  "Initial Access"),
    "Phishing_Fake": ("T1056.003", "Web Portal Capture",                  "Collection"),
}


def map_techniques(
    ioc_types: list[str],
    spf: str,
    dkim: str,
    dmarc: str,
    has_reply_to_mismatch: bool,
    has_urgency: bool,
    has_dangerous_attachment: bool,
    yara_rule_names: list[str],
) -> list[ATTACKTechnique]:
    """
    Returns deduplicated list of ATT&CK techniques mapped from all evidence sources.
    """
    techniques: dict[str, ATTACKTechnique] = {}

    def _add(t_id, name, tactic, desc, confidence, source):
        if t_id not in techniques:
            techniques[t_id] = ATTACKTechnique(
                technique_id=t_id, name=name, tactic=tactic,
                description=desc, confidence=confidence, source=source,
            )

    # IOC-based
    for ioc_type in set(ioc_types):
        for entry in _IOC_TECHNIQUE_MAP.get(ioc_type, []):
            _add(entry["technique_id"], entry["name"], entry["tactic"],
                 entry["description"], entry["confidence"], f"IOC:{ioc_type}")

    # Auth-based
    if spf in ("fail", "softfail"):
        e = _AUTH_TECHNIQUE_MAP["spf_fail"]
        _add(e["technique_id"], e["name"], e["tactic"], e["description"], e["confidence"], "SPF")
    if dkim in ("fail",):
        e = _AUTH_TECHNIQUE_MAP["dkim_fail"]
        _add(e["technique_id"], e["name"], e["tactic"], e["description"], e["confidence"], "DKIM")
    if dmarc in ("fail",):
        e = _AUTH_TECHNIQUE_MAP["dmarc_fail"]
        _add(e["technique_id"], e["name"], e["tactic"], e["description"], e["confidence"], "DMARC")

    # Heuristic-based
    if has_reply_to_mismatch:
        e = _HEURISTIC_TECHNIQUE_MAP["reply_to_mismatch"]
        _add(e["technique_id"], e["name"], e["tactic"], e["description"], e["confidence"], "Heuristic:reply-to")
    if has_urgency:
        e = _HEURISTIC_TECHNIQUE_MAP["urgency_keywords"]
        _add(e["technique_id"], e["name"], e["tactic"], e["description"], e["confidence"], "Heuristic:urgency")
    if has_dangerous_attachment:
        e = _HEURISTIC_TECHNIQUE_MAP["dangerous_attachment"]
        _add(e["technique_id"], e["name"], e["tactic"], e["description"], e["confidence"], "Heuristic:attachment")

    # YARA-based
    for rule_name in yara_rule_names:
        for prefix, (t_id, name, tactic) in _YARA_TECHNIQUE_MAP.items():
            if rule_name.startswith(prefix):
                _add(t_id, name, tactic, f"Detected by YARA rule: {rule_name}", "high", f"YARA:{rule_name}")

    # Sort: high confidence first, then by tactic
    return sorted(techniques.values(),
                  key=lambda t: ({"high": 0, "medium": 1, "low": 2}.get(t.confidence, 3), t.tactic))
