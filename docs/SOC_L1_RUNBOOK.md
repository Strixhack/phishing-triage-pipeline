# SOC L1 Analyst Runbook — Phishing Triage Pipeline

**Version:** 1.0  
**Audience:** SOC L1 Analysts  
**Classification:** Internal

---

## 1. Overview

This runbook covers the end-to-end workflow for triaging phishing emails using the
Phishing Triage Pipeline. All cases pass through automated analysis before reaching
the analyst queue. Your job is to review, validate, and escalate.

---

## 2. Triage Workflow

```
Email received → Upload .eml → Automated scoring → Analyst review → Escalate or close
```

### Step 1 — Upload
- Navigate to **Upload** in the left sidebar
- Drag and drop the `.eml` file (export from Outlook/Thunderbird)
- Wait for automated analysis (~5–15 seconds)

### Step 2 — Review automated verdict
| Score | Verdict    | Default action          |
|-------|------------|------------------------|
| 0–29  | BENIGN     | Review then close      |
| 30–59 | SUSPICIOUS | Investigate, escalate if confirmed |
| 60–100| MALICIOUS  | Escalate to L2 immediately |

### Step 3 — Check auth results
| Result | Meaning                                 | Action          |
|--------|-----------------------------------------|-----------------|
| SPF PASS + DKIM PASS + DMARC PASS | Likely legitimate | Proceed with content review |
| Any FAIL | Spoofing likely | Increase suspicion level |
| All FAIL | Strong spoofing indicator | Treat as malicious unless proven otherwise |

### Step 4 — Review IOCs
- Click the case reference to open the Case Detail view
- Review each IOC and its enrichment scores:
  - **VirusTotal score > 20%** → suspicious, > 50% → malicious
  - **AbuseIPDB score > 25** → suspicious, > 50% → malicious
  - **MISP hits > 0** → known threat actor, escalate
- Note: IOCs with **risk score > 60** are highlighted in red

### Step 5 — Take action
Use the analyst action buttons in the Case Detail view:
- **Change verdict** — override automated verdict if evidence warrants
- **Escalation** — set to L2 or CISO as appropriate (see Section 3)
- **Add note** — document your reasoning (mandatory for all MALICIOUS cases)
- **Mark as Notified** — only after NIS2 notification has been sent (see Section 4)

---

## 3. Escalation Matrix

| Verdict     | IOC severity | Action                       | SLA     |
|-------------|-------------|------------------------------|---------|
| BENIGN      | Any         | Close with note              | 4h      |
| SUSPICIOUS  | Low         | Monitor, re-review in 2h     | 2h      |
| SUSPICIOUS  | Medium/High | Escalate to L2               | 1h      |
| MALICIOUS   | Any         | Escalate to L2 immediately   | 30 min  |
| MALICIOUS + MISP hit | Any | Escalate to CISO immediately | 15 min |

**To escalate:** Open the case → Analyst Actions → click **L2** or **CISO** button.

---

## 4. NIS2 Notification Procedure

NIS2 (EU 2022/2555) Article 23 mandates notification for **significant incidents**.

A case is flagged as **significant** when:
- Verdict is MALICIOUS, or
- Risk score ≥ 60

**Notification timeline:**

| Deadline | Action required |
|----------|----------------|
| **T+24h** | Early warning to national CSIRT / competent authority |
| **T+72h** | Full incident notification with impact assessment |

**Steps:**
1. Navigate to **NIS2** in the left sidebar
2. Review the compliance status of each significant case
3. Cases shown in **red** are overdue — escalate to CISO immediately
4. After sending notification to your authority, return to the case and click **Mark as Notified**

> ⚠ Do not wait for T+72h to begin the process. The 24h early warning is mandatory
> even if the investigation is incomplete. Send what you know.

---

## 5. Common Scenarios

### Scenario A — Obvious phishing
SPF/DKIM/DMARC all fail + malicious URLs detected + MISP hits:
→ Verdict: MALICIOUS → Escalate to L2 → Add note → NIS2 if score ≥ 60

### Scenario B — Suspicious but inconclusive
Mixed auth results + moderate VT scores + no MISP hits:
→ Verdict: SUSPICIOUS → Escalate to L2 → Request full headers from sender's mail admin

### Scenario C — Likely false positive
SPF/DKIM/DMARC pass + low scores + benign subject + internal sender:
→ Verdict: BENIGN → Add note explaining why → Close

### Scenario D — NIS2 overdue
Case shows **OVERDUE** in NIS2 dashboard:
→ Immediately notify CISO → Send late notification to authority → Document in case

---

## 6. Evidence Preservation

For all MALICIOUS cases, before closing:
- Export the case (Export button → JSON) and save to evidence folder
- The audit log is immutable and will be preserved automatically
- Do not delete or modify the original `.eml` file

---

## 7. Contacts

| Role   | Contact |
|--------|---------|
| SOC L2 | [Your L2 contact] |
| CISO   | [Your CISO contact] |
| National CSIRT | [Country-specific — e.g. BSI for Germany, NCSC for Netherlands] |
