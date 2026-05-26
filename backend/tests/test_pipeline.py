"""
Tests for email parser and risk scorer.
Run with: pytest backend/tests/ -v
"""
import pytest
from app.services.email_parser import parse_eml
from app.services.risk_scorer import score_case, IOCEnrichment


# ── Sample .eml fixtures ──────────────────────────────────────────────────────

CLEAN_EML = b"""\
From: alice@legitimate.com
To: bob@company.com
Subject: Q3 report attached
Message-ID: <abc123@legitimate.com>
Date: Mon, 14 Oct 2024 09:00:00 +0000
Authentication-Results: mx.company.com;
  spf=pass smtp.mailfrom=legitimate.com;
  dkim=pass header.d=legitimate.com;
  dmarc=pass

Hi Bob,

Please find the Q3 report attached.

Best,
Alice
"""

PHISHING_EML = b"""\
From: security@paypal-login-verify.evil.com
To: victim@company.com
Reply-To: harvester@attacker.ru
Subject: URGENT: Your account has been suspended - verify now
Message-ID: <xyz@evil.com>
Date: Mon, 14 Oct 2024 09:00:00 +0000
Authentication-Results: mx.company.com;
  spf=fail smtp.mailfrom=evil.com;
  dkim=fail header.d=evil.com;
  dmarc=fail

Your PayPal account is suspended. Click here to verify:
http://malware-phish.evil.com/login?token=abc123

Failure to act will result in permanent suspension.
"""


# ── Parser tests ──────────────────────────────────────────────────────────────

def test_parse_clean_email():
    result = parse_eml(CLEAN_EML)
    assert result.sender == "alice@legitimate.com"
    assert result.subject == "Q3 report attached"
    assert result.spf == "pass"
    assert result.dkim == "pass"
    assert result.dmarc == "pass"
    assert result.urls == []


def test_parse_phishing_email():
    result = parse_eml(PHISHING_EML)
    assert result.spf == "fail"
    assert result.dkim == "fail"
    assert result.dmarc == "fail"
    assert len(result.urls) == 1
    assert "malware-phish.evil.com" in result.urls[0]
    assert result.reply_to == "harvester@attacker.ru"


def test_parse_extracts_domains():
    result = parse_eml(PHISHING_EML)
    assert "malware-phish.evil.com" in result.domains


# ── Scorer tests ──────────────────────────────────────────────────────────────

def test_score_clean_email():
    result = parse_eml(CLEAN_EML)
    scoring = score_case(result, [])
    assert scoring.verdict == "benign"
    assert scoring.total < 30


def test_score_phishing_email():
    result = parse_eml(PHISHING_EML)
    enrichments = [
        IOCEnrichment(
            value="http://malware-phish.evil.com/login",
            ioc_type="url",
            vt_score=0.6,
            misp_hits=2,
        )
    ]
    scoring = score_case(result, enrichments)
    assert scoring.verdict in ("suspicious", "malicious")
    assert scoring.total >= 30


def test_score_auth_failures_raise_score():
    result = parse_eml(PHISHING_EML)
    scoring = score_case(result, [])
    # SPF+DKIM+DMARC all fail — auth component should be non-zero
    assert scoring.breakdown["auth"] > 0


def test_reply_to_mismatch_detected():
    result = parse_eml(PHISHING_EML)
    scoring = score_case(result, [])
    assert scoring.breakdown["heuristics"] > 0


def test_malicious_verdict_at_high_score():
    result = parse_eml(PHISHING_EML)
    enrichments = [
        IOCEnrichment(
            value="http://evil.com/payload.exe",
            ioc_type="url",
            vt_score=0.85,
            abuseipdb_score=95.0,
            misp_hits=3,
        )
    ]
    scoring = score_case(result, enrichments)
    assert scoring.verdict == "malicious"
    assert scoring.total >= 60
