"""
Email Parser Service
Parses raw .eml bytes → structured EmailParseResult with IOCs and auth results.
"""
import email
import hashlib
import re
from dataclasses import dataclass, field
from email import policy


# ── Regex patterns ────────────────────────────────────────────────────────────
_URL_RE    = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
_IP_RE     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_EMAIL_RE  = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
_DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b')
_MD5_RE    = re.compile(r'\b[a-fA-F0-9]{32}\b')
_SHA1_RE   = re.compile(r'\b[a-fA-F0-9]{40}\b')
_SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')

# Private / RFC-1918 ranges — skip these IPs
_PRIVATE_IP_PREFIXES = ("10.", "192.168.", "127.", "0.")
_PRIVATE_IP_172 = tuple(f"172.{i}." for i in range(16, 32))


@dataclass
class EmailParseResult:
    subject: str = ""
    sender: str = ""
    recipient: str = ""
    message_id: str = ""
    date: str = ""
    received_chain: list[str] = field(default_factory=list)
    reply_to: str = ""

    # Auth
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"

    # Body
    plain_text: str = ""
    html_body: str = ""
    attachments: list[dict] = field(default_factory=list)

    # IOCs (deduplicated)
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    emails_found: list[str] = field(default_factory=list)


def parse_eml(raw_bytes: bytes) -> EmailParseResult:
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    result = EmailParseResult()

    # ── Basic headers ──────────────────────────────────────────────────────────
    result.subject   = str(msg.get("Subject", ""))
    result.sender    = str(msg.get("From", ""))
    result.recipient = str(msg.get("To", ""))
    result.message_id = str(msg.get("Message-ID", ""))
    result.date      = str(msg.get("Date", ""))
    result.reply_to  = str(msg.get("Reply-To", ""))
    result.received_chain = msg.get_all("Received") or []

    # ── Auth-Results header ────────────────────────────────────────────────────
    auth_results = " ".join(msg.get_all("Authentication-Results") or []).lower()
    result.spf   = _extract_auth(auth_results, "spf")
    result.dkim  = _extract_auth(auth_results, "dkim")
    result.dmarc = _extract_auth(auth_results, "dmarc")

    # ── Body extraction ────────────────────────────────────────────────────────
    body_text = ""
    for part in msg.walk():
        ct = part.get_content_type()
        cd = str(part.get("Content-Disposition", ""))
        if "attachment" in cd:
            payload = part.get_payload(decode=True) or b""
            result.attachments.append({
                "filename": part.get_filename("unnamed"),
                "content_type": ct,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "md5": hashlib.md5(payload).hexdigest(),
            })
            result.hashes.append(hashlib.sha256(payload).hexdigest())
        elif ct == "text/plain":
            result.plain_text = part.get_content() or ""
            body_text += result.plain_text
        elif ct == "text/html":
            result.html_body = part.get_content() or ""
            body_text += result.html_body

    # ── IOC extraction ─────────────────────────────────────────────────────────
    search_space = body_text + " " + " ".join(result.received_chain)
    result.urls    = _dedup(_URL_RE.findall(search_space))
    result.ips     = _dedup([ip for ip in _IP_RE.findall(search_space) if _is_public_ip(ip)])
    result.domains = _dedup(_extract_domains(result.urls))
    result.hashes  = _dedup(
        result.hashes
        + _SHA256_RE.findall(search_space)
        + _SHA1_RE.findall(search_space)
        + _MD5_RE.findall(search_space)
    )
    result.emails_found = _dedup(_EMAIL_RE.findall(search_space))

    return result


# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_auth(header: str, protocol: str) -> str:
    for keyword in ("pass", "fail", "softfail", "neutral", "none", "permerror", "temperror"):
        pattern = rf"{protocol}=({keyword})"
        if re.search(pattern, header):
            return keyword
    return "none"


def _is_public_ip(ip: str) -> bool:
    if ip.startswith(_PRIVATE_IP_PREFIXES):
        return False
    if any(ip.startswith(p) for p in _PRIVATE_IP_172):
        return False
    return True


def _extract_domains(urls: list[str]) -> list[str]:
    domains = []
    for url in urls:
        m = re.match(r'https?://([^/:?#\s]+)', url)
        if m:
            domains.append(m.group(1))
    return domains


def _dedup(lst: list[str]) -> list[str]:
    seen = set()
    out = []
    for item in lst:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out
