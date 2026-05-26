"""
YARA Scanning Service
Scans email body text and attachment contents against YARA rules.
Returns matched rules with severity, MITRE ATT&CK technique, and tags.
"""
from __future__ import annotations
import os
import yara
from dataclasses import dataclass, field
from pathlib import Path

RULES_DIR = Path(__file__).parent.parent.parent / "yara_rules"
_compiled_rules: yara.Rules | None = None


def _get_rules() -> yara.Rules:
    global _compiled_rules
    if _compiled_rules is None:
        rule_files = {}
        for yar in RULES_DIR.glob("*.yar"):
            rule_files[yar.stem] = str(yar)
        if rule_files:
            _compiled_rules = yara.compile(filepaths=rule_files)
        else:
            _compiled_rules = yara.compile(source="rule Empty { condition: false }")
    return _compiled_rules


@dataclass
class YARAMatch:
    rule_name: str
    description: str
    severity: str      # critical / high / medium / low
    mitre: str         # ATT&CK technique ID
    tags: list[str]
    matched_strings: list[str]


@dataclass
class YARAScanResult:
    matches: list[YARAMatch] = field(default_factory=list)
    highest_severity: str = "none"
    mitre_techniques: list[str] = field(default_factory=list)
    score_contribution: float = 0.0   # 0–100 added to risk score


_SEVERITY_SCORE = {
    "critical": 40.0,
    "high":     25.0,
    "medium":   10.0,
    "low":       5.0,
    "none":      0.0,
}

_SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]


def scan_content(
    body_text: str = "",
    html_body: str = "",
    attachment_data: list[bytes] | None = None,
) -> YARAScanResult:
    """
    Scans email body text, HTML, and attachment bytes against YARA rules.
    Returns aggregated YARAScanResult.
    """
    rules = _get_rules()
    result = YARAScanResult()

    targets: list[bytes] = []
    if body_text:
        targets.append(body_text.encode("utf-8", errors="replace"))
    if html_body:
        targets.append(html_body.encode("utf-8", errors="replace"))
    if attachment_data:
        targets.extend(attachment_data)

    seen_rules: set[str] = set()

    for data in targets:
        try:
            matches = rules.match(data=data)
        except Exception:
            continue

        for match in matches:
            if match.rule in seen_rules:
                continue
            seen_rules.add(match.rule)

            meta      = match.meta or {}
            severity  = meta.get("severity", "medium")
            mitre     = meta.get("mitre", "")
            tags_str  = meta.get("tags", "")
            tags      = [t.strip() for t in tags_str.split(",") if t.strip()]
            desc      = meta.get("description", match.rule)

            matched_strings = []
            for s in match.strings:
                for instance in s.instances:
                    try:
                        matched_strings.append(instance.matched_data.decode("utf-8", errors="replace")[:80])
                    except Exception:
                        pass

            result.matches.append(YARAMatch(
                rule_name=match.rule,
                description=desc,
                severity=severity,
                mitre=mitre,
                tags=tags,
                matched_strings=list(set(matched_strings))[:5],
            ))

            if mitre and mitre not in result.mitre_techniques:
                result.mitre_techniques.append(mitre)

    # Highest severity
    if result.matches:
        severities = [m.severity for m in result.matches]
        result.highest_severity = max(severities, key=lambda s: _SEVERITY_ORDER.index(s) if s in _SEVERITY_ORDER else 0)

    # Score contribution — capped at 100
    total = sum(_SEVERITY_SCORE.get(m.severity, 0) for m in result.matches)
    result.score_contribution = min(100.0, total)

    return result
