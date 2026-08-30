"""
risk_engine.py — PhishGuard Risk Engine
========================================
Aggregates results from the sender, URL, and content analyzers into a
final risk verdict that exactly matches the frontend's expected JSON shape.

Scoring weights (must sum to 100):
  sender_weight      = 30%   — who sent it matters most for quick detection
  links_weight       = 35%   — malicious URLs are the primary delivery mechanism
  content_weight     = 20%   — social-engineering cues are important but secondary
  attachment_weight  = 15%   — attachments can deliver malware directly

Aggregation strategy (max-boost):
  base  = sender*0.35 + links*0.40 + content*0.25  (weighted average)
  boost = max(sender, links, content) * 0.80        (dominant-signal lift)
  overall = max(base, boost)

  Rationale: a simple weighted average can mask a single HIGH-severity
  vector (e.g. typosquatting domain + credential solicitation) when the
  other categories score lower.  The boost ensures that if ANY sub-score
  is clearly malicious (>= 65), the overall score rises to at least 52
  (0.80 * 65), and typically much higher.  With sub-scores >= 80 the boost
  alone reaches 64+, pushing the verdict to HIGH.

Risk level thresholds:
  score >= 65  -> HIGH
  score >= 35  -> MEDIUM
  score <  35  -> LOW

Sender analysis is performed inline in this module since it is tightly
coupled to the parsed email fields (domain, display name, etc.).
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from .email_parser     import ParsedEmail
from .url_analyzer     import UrlAnalysisResult
from .content_analyzer import ContentAnalysisResult
from .attachment_analyzer import AttachmentAnalysisResult
from .header_analyzer  import HeaderAnalysisResult


# ── Scoring weights ───────────────────────────────────────────────────────────
# Total must sum to 1.0. The header/auth layer is new; weights are shifted so
# the existing four vectors retain their relative ordering while also giving
# authentication meaningful weight (per the product spec: header signals 0–20).
SENDER_WEIGHT      = 0.25
LINKS_WEIGHT       = 0.30
CONTENT_WEIGHT     = 0.15
ATTACHMENT_WEIGHT  = 0.10
HEADER_WEIGHT      = 0.20

# ── Risk level thresholds ─────────────────────────────────────────────────────
HIGH_THRESHOLD   = 65
MEDIUM_THRESHOLD = 35

# ── Suspicious sender patterns ────────────────────────────────────────────────

# Keywords in FROM display name that imply a big brand but domain doesn't match
BRAND_KEYWORDS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
    "apple":  ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "microsoft": ["microsoft.com", "outlook.com", "hotmail.com", "live.com"],
    "netflix": ["netflix.com"],
    "bank of america": ["bankofamerica.com"],
    "chase": ["chase.com", "jpmorgan.com"],
    "wells fargo": ["wellsfargo.com"],
    "ebay": ["ebay.com"],
    "irs": ["irs.gov"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "dhl": ["dhl.com"],
}

# Characters/patterns that are suspicious in a domain name
SUSPICIOUS_DOMAIN_CHARS = re.compile(r'(\d{4,}|--|\.{2,})')

# Free email providers — fine on their own but suspicious if claiming a brand
FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "mail.com", "yandex.com",
    "gmx.com", "icloud.com", "live.com",
}

# Suspicious keywords inside a sender domain
SUSPICIOUS_DOMAIN_KEYWORDS = [
    "secure", "login", "verify", "update", "account", "support",
    "helpdesk", "service", "confirm", "auth", "validation",
]


@dataclass
class SenderFinding:
    label:  str
    detail: str
    points: int


@dataclass
class SenderAnalysisResult:
    score:    int = 0
    findings: List[SenderFinding] = field(default_factory=list)
    summary:  str = ""


@dataclass
class RiskResult:
    """Final risk verdict — exactly matches the frontend API contract.

    `confidence` (0–1) is distinct from `score`: score measures how much
    suspicious *evidence* was found, while confidence measures how much
    reliable evidence the analysis was actually based on (a pasted email
    with no headers yields lower confidence even when an indicator fires).
    """
    score:          int             # 0–100 overall threat score
    level:          str             # "HIGH" | "MEDIUM" | "LOW"
    breakdown:      Dict[str, int]  # {sender, links, content, attachment, header}
    threats:        List[Dict]      # threat-card objects
    findings:       List[Dict]      # finding-row objects
    recommendation: str
    confidence:     float = 0.0     # 0.0–1.0 detection confidence
    authentication: Dict = field(default_factory=dict)  # SPF/DKIM/DMARC + present
    evidence:       List[str] = field(default_factory=list)  # human-readable "why" bullets
    classification: str = ""        # likely_phishing | suspicious | likely_benign


# ── Sender Analysis ───────────────────────────────────────────────────────────

def analyze_sender(parsed: ParsedEmail) -> SenderAnalysisResult:
    """
    Rule-based scoring of the sender address and domain.

    Rules:
      [S1] No From address found                    → +30 (can't verify anything)
      [S2] Sender from free provider claiming brand → +40
      [S3] Brand name in display name but wrong dom → +45
      [S4] Suspicious keywords in domain            → +20
      [S5] Excessive hyphens in domain (≥2)         → +15
      [S6] Domain looks like a brand with typo      → +35
      [S7] Very new-looking or random domain        → +10
    """
    result = SenderAnalysisResult()
    total = 0

    if not parsed.from_address:
        result.findings.append(SenderFinding(
            label="Missing Sender Address",
            detail="No From: address could be extracted. Legitimate emails always have a clear sender.",
            points=30
        ))
        total += 30
        result.score = min(total, 100)
        result.summary = "Sender address could not be determined."
        return result

    domain = parsed.from_domain or ""
    name   = (parsed.from_name or "").lower()

    # [S2+S3] Brand impersonation check
    for brand, legit_domains in BRAND_KEYWORDS.items():
        brand_in_name = brand in name
        brand_in_addr = brand in parsed.from_address.lower()

        if brand_in_name or brand_in_addr:
            # Check if domain is actually legitimate
            is_legit = any(domain == ld or domain.endswith("." + ld) for ld in legit_domains)
            if not is_legit:
                # From free provider while claiming brand
                if domain in FREE_EMAIL_PROVIDERS:
                    pts = 40
                    total += pts
                    result.findings.append(SenderFinding(
                        label="Brand Impersonation via Free Email",
                        detail=f"Email claims to be from '{brand.title()}' but was sent from a free email provider ({domain}). Legitimate organizations use their own domains.",
                        points=pts
                    ))
                else:
                    pts = 45
                    total += pts
                    result.findings.append(SenderFinding(
                        label="Sender Domain Mismatch",
                        detail=f"Display name references '{brand.title()}' but the actual sending domain ({domain}) does not match any known '{brand.title()}' domain. Classic impersonation.",
                        points=pts
                    ))

    # [S4] Suspicious keywords in domain
    kw_hits = [kw for kw in SUSPICIOUS_DOMAIN_KEYWORDS if kw in domain]
    if kw_hits:
        pts = 20
        total += pts
        result.findings.append(SenderFinding(
            label="Suspicious Keywords in Sender Domain",
            detail=f"The sender domain ({domain}) contains keywords often used in phishing domains: {', '.join(kw_hits)}.",
            points=pts
        ))

    # [S5] Excessive hyphens
    if domain.count("-") >= 2:
        pts = 15
        total += pts
        result.findings.append(SenderFinding(
            label="Excessive Hyphens in Sender Domain",
            detail=f"The domain '{domain}' contains {domain.count('-')} hyphens, which is a common pattern in phishing domains.",
            points=pts
        ))

    # [S6] Typosquatting — domain closely resembles a brand but isn't it
    for brand, legit_domains in BRAND_KEYWORDS.items():
        for ld in legit_domains:
            brand_core = ld.split(".")[0]  # e.g. "paypal"
            # Check for common substitutions: 0→o, 1→l, rn→m, etc.
            normalized_domain = (
                domain
                .replace("0", "o")
                .replace("1", "l")
                .replace("rn", "m")
                .replace("vv", "w")
            )
            if brand_core in normalized_domain and domain != ld and domain not in legit_domains:
                pts = 35
                total += pts
                result.findings.append(SenderFinding(
                    label="Possible Typosquatting Domain",
                    detail=f"The sender domain ({domain}) appears to be a misspelled or manipulated version of '{ld}'. Possible lookalike domain attack.",
                    points=pts
                ))
                break  # Only flag once per brand

    # [S7] Very short random-looking domain (no brand hit, random chars)
    domain_base = domain.split(".")[0] if "." in domain else domain
    if len(domain_base) <= 4 and not any(b in domain for b in BRAND_KEYWORDS):
        pts = 10
        total += pts
        result.findings.append(SenderFinding(
            label="Short or Random-Looking Domain",
            detail=f"The sender domain '{domain}' has a very short base ({domain_base!r}) which may indicate a throwaway or newly registered phishing domain.",
            points=pts
        ))

    result.score = min(total, 100)

    # Build summary
    if result.findings:
        labels = [f.label for f in result.findings]
        result.summary = f"Sender analysis flagged {len(result.findings)} issue(s): {'; '.join(labels)}."
    else:
        result.summary = f"No suspicious indicators found for sender domain ({domain})."

    return result


# ── Risk Engine ───────────────────────────────────────────────────────────────

def build_risk_result(
    parsed:          ParsedEmail,
    sender_result:   SenderAnalysisResult,
    url_result:      UrlAnalysisResult,
    content_result:  ContentAnalysisResult,
    attachment_result: AttachmentAnalysisResult,
    header_result:   HeaderAnalysisResult,
) -> RiskResult:
    """
    Combine sub-scores into a final RiskResult that matches the frontend contract.

    Aggregation (max-boost):
      base    = sender*0.25 + links*0.30 + content*0.15 + attachment*0.10 + header*0.20
      boost   = max(sender, links, content, attachment, header) * 0.80
      overall = max(base, boost)

    This prevents a single clearly-malicious sub-score from being diluted
    to MEDIUM by weaker signals in the other categories.
    """

    # ── Weighted average (base) ───────────────────────────────────────────────
    base = (
        sender_result.score      * SENDER_WEIGHT      +
        url_result.score         * LINKS_WEIGHT       +
        content_result.score     * CONTENT_WEIGHT     +
        attachment_result.score  * ATTACHMENT_WEIGHT  +
        header_result.score      * HEADER_WEIGHT
    )

    # ── Dominant-signal boost ─────────────────────────────────────────────────
    # If any single sub-score is clearly malicious, prevent it from being
    # diluted down to MEDIUM by low scores in other categories.
    # The boost is 80 % of the highest individual sub-score.
    max_sub  = max(
        sender_result.score,
        url_result.score,
        content_result.score,
        attachment_result.score,
        header_result.score,
    )
    boost    = max_sub * 0.80

    overall  = int(max(base, boost))
    overall  = max(0, min(overall, 100))

    # ── Risk level ────────────────────────────────────────────────────────────
    if overall >= HIGH_THRESHOLD:
        level = "HIGH"
    elif overall >= MEDIUM_THRESHOLD:
        level = "MEDIUM"
    else:
        level = "LOW"

    # ── Classification ────────────────────────────────────────────────────────
    if level == "HIGH":
        classification = "likely_phishing"
    elif level == "MEDIUM":
        classification = "suspicious"
    else:
        classification = "likely_benign"

    # ── Breakdown ─────────────────────────────────────────────────────────────
    breakdown = {
        "sender":     sender_result.score,
        "links":      url_result.score,
        "content":    content_result.score,
        "attachment": attachment_result.score,
        "header":     header_result.score,
    }

    # ── Confidence ────────────────────────────────────────────────────────────
    confidence = _compute_confidence(parsed, header_result, sender_result, url_result, content_result, attachment_result)

    # ── Threat cards ──────────────────────────────────────────────────────────
    threats = _build_threats(sender_result, url_result, content_result, attachment_result, header_result, level)

    # ── Findings list ─────────────────────────────────────────────────────────
    findings = _build_findings(sender_result, url_result, content_result, attachment_result, header_result)

    # ── Evidence ("why was this flagged") ─────────────────────────────────────
    evidence = _build_evidence(level, sender_result, url_result, content_result, attachment_result, header_result)

    # ── Recommendation ────────────────────────────────────────────────────────
    recommendation = _build_recommendation(level, sender_result, url_result, content_result, attachment_result, header_result)

    # ── Authentication summary ────────────────────────────────────────────────
    authentication = {
        "spf":    header_result.auth.spf,
        "dkim":   header_result.auth.dkim,
        "dmarc":  header_result.auth.dmarc,
        "present": header_result.auth.present,
    }

    return RiskResult(
        score=overall,
        level=level,
        breakdown=breakdown,
        threats=threats,
        findings=findings,
        recommendation=recommendation,
        confidence=confidence,
        authentication=authentication,
        evidence=evidence,
        classification=classification,
    )


def _compute_confidence(parsed, header_result, sender_result, url_result, content_result, attachment_result) -> float:
    """
    Estimate how much reliable evidence the analysis was based on.

    Starts at 1.0 and reduces when key data is missing:
      - No structured headers / no auth evidence  → -0.35 (can't verify spoofing)
      - No From address                           → -0.25 (can't verify sender)
      - Very low content score with no findings   → -0.10
    The value is clamped to [0, 1] and rounded to 2 decimals.
    """
    c = 1.0

    if not parsed.has_headers or not header_result.auth.present:
        c -= 0.35
    if not parsed.from_address:
        c -= 0.25
    if content_result.score == 0 and not content_result.findings:
        c -= 0.10

    c = max(0.0, min(1.0, c))
    return round(c, 2)


# ── Threat card builder ───────────────────────────────────────────────────────

def _build_threats(sender, url, content, attachment, header, overall_level) -> List[Dict]:
    """
    Build the threat-card objects expected by the frontend:
      sender, url, urgency, attachment, auth
    Severity is derived from sub-scores and matched findings.
    """

    def _sev(score: int) -> str:
        if score >= 65: return "HIGH"
        if score >= 35: return "MEDIUM"
        return "SAFE"

    # Sender threat
    sender_sev = _sev(sender.score)
    if sender_sev == "HIGH":
        sender_desc = sender.findings[0].detail if sender.findings else "Suspicious sender detected."
    elif sender_sev == "MEDIUM":
        sender_desc = "Sender domain raised some concerns. Verify before acting."
    else:
        sender_desc = "Sender address appears legitimate. No impersonation detected."

    # URL / Links threat
    url_sev = _sev(url.score)
    if url_sev == "HIGH":
        url_desc = f"{len(url.urls)} URL(s) detected with high-risk indicators (e.g. IP host, brand keyword in domain, shortener)."
    elif url_sev == "MEDIUM":
        url_desc = f"{len(url.urls)} URL(s) detected with moderate risk indicators. Verify before clicking."
    else:
        url_desc = f"{len(url.urls)} URL(s) found — no major suspicious patterns detected." if url.urls else "No URLs found in the email."

    # Content / urgency threat — use category hits
    urgency_cats = set(f.category for f in content.findings)
    if "C1" in urgency_cats or "C3" in urgency_cats:
        urg_sev = "HIGH" if content.score >= 40 else "MEDIUM"
        urg_desc = "Email uses urgency or fear language to pressure the recipient into immediate action."
    elif "C2" in urgency_cats or "C4" in urgency_cats:
        urg_sev = "MEDIUM"
        urg_desc = "Email contains credential requests or financial lure language."
    elif urgency_cats:
        urg_sev = "LOW"
        urg_desc = "Mild persuasive language detected but below high-risk threshold."
    else:
        urg_sev = "SAFE"
        urg_desc = "No urgency or manipulation patterns detected."

    # Attachment — real analysis based on attachment sub-score
    attach_sev = _sev(attachment.score)
    if attach_sev == "HIGH":
        attach_desc = attachment.findings[0].detail if attachment.findings else "Suspicious attachment detected."
    elif attach_sev == "MEDIUM":
        attach_desc = "Attachment(s) raised some concerns (archive, MIME type, or filename lure). Treat attached files with caution."
    elif attachment.attachments:
        attach_desc = f"{len(attachment.attachments)} attachment(s) found — no major suspicious patterns detected."
    else:
        attach_desc = "No attachments found in the email."

    # Header / authentication threat
    auth_sev = _sev(header.score)
    if auth_sev == "HIGH":
        auth_desc = header.findings[0].detail if header.findings else "Header/authentication indicators are suspicious."
    elif auth_sev == "MEDIUM":
        auth_desc = "Header or authentication indicators raised some concerns (Reply-To/Return-Path mismatch or auth failures)."
    elif not header.has_headers:
        auth_desc = "No full header block provided — authentication could not be verified."
    else:
        auth_desc = "Header alignment and authentication results appear healthy."

    return [
        {"id": "sender",     "title": "Sender Analysis",       "description": sender_desc,     "severity": sender_sev,     "icon": "user-x"},
        {"id": "url",        "title": "URL / Link Analysis",    "description": url_desc,        "severity": url_sev,        "icon": "link"},
        {"id": "urgency",    "title": "Content & Manipulation", "description": urg_desc,        "severity": urg_sev,        "icon": "alert-triangle"},
        {"id": "attachment", "title": "Attachment Risk",        "description": attach_desc,     "severity": attach_sev,     "icon": "paperclip"},
        {"id": "auth",       "title": "Header & Authentication","description": auth_desc,        "severity": auth_sev,       "icon": "shield"},
    ]


# ── Findings list builder ─────────────────────────────────────────────────────

def _build_findings(sender, url, content, attachment, header) -> List[Dict]:
    """
    Flatten all granular findings from the five analyzers into a single list
    of finding-row dicts. Each gets a unique sequential ID (f1, f2, …).
    """
    rows = []
    idx  = 1

    # Sender findings
    for f in sender.findings:
        sev = "HIGH" if f.points >= 30 else "MEDIUM" if f.points >= 15 else "LOW"
        rows.append({
            "id":       f"f{idx}",
            "label":    f.label,
            "text":     f.detail,
            "severity": sev,
        })
        idx += 1

    # URL findings
    for f in url.findings:
        sev = "HIGH" if f.points >= 25 else "MEDIUM" if f.points >= 12 else "LOW"
        rows.append({
            "id":       f"f{idx}",
            "label":    f"URL Risk [{f.rule_id}]",
            "text":     f.detail,
            "severity": sev,
        })
        idx += 1

    # Content findings
    for f in content.findings:
        sev = "HIGH" if f.points >= 18 else "MEDIUM" if f.points >= 10 else "LOW"
        rows.append({
            "id":       f"f{idx}",
            "label":    f.label,
            "text":     f"Detected in email: {f.excerpt}",
            "severity": sev,
        })
        idx += 1

    # Attachment findings
    for f in attachment.findings:
        sev = "HIGH" if f.points >= 25 else "MEDIUM" if f.points >= 12 else "LOW"
        rows.append({
            "id":       f"f{idx}",
            "label":    f"Attachment Risk [{f.rule}]",
            "text":     f.detail,
            "severity": sev,
        })
        idx += 1

    # Header / authentication findings
    for f in header.findings:
        sev = f.severity
        rows.append({
            "id":       f"f{idx}",
            "label":    f.label,
            "text":     f.detail,
            "severity": sev,
        })
        idx += 1

    # If no findings at all, add a positive SAFE finding
    if not rows:
        rows.append({
            "id":       "f1",
            "label":    "No Threats Detected",
            "text":     "All analyzed indicators appear safe. The email shows no signs of phishing.",
            "severity": "SAFE",
        })

    return rows


# ── Evidence builder ──────────────────────────────────────────────────────────

def _build_evidence(level, sender, url, content, attachment, header) -> List[str]:
    """
    Produce a concise, human-readable list of reasons the email was flagged —
    the "why this email was flagged" / evidence section. Each item reads as a
    standalone explanation of a distinct issue. Falls back to a reassuring
    note when the email looks clean.
    """
    items: List[str] = []

    for f in sender.findings:
        if f.points >= 15:
            items.append(f"Sender: {f.detail}")

    for f in url.findings:
        if f.points >= 12:
            items.append(f"Link: {f.detail}")

    for f in content.findings:
        if f.points >= 10:
            items.append(f"Language: {f.label}.")

    for f in attachment.findings:
        if f.points >= 12:
            items.append(f"Attachment: {f.detail}")

    for f in header.findings:
        items.append(f"{f.label}: {f.detail}")

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for item in items:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    items = unique

    if not items:
        if level == "HIGH":
            items.append("Score reached HIGH despite few granular signals — dominant threat vector detected.")
        else:
            items.append("No high-confidence suspicious indicators were detected in this email.")

    # Always end with the core takeaway.
    items.append(
        "This summary is based on deterministic rule-based indicators; authentication "
        "failures or sender mismatches are treated as risk signals, not proof of malice."
    )

    return items


# ── Recommendation builder ────────────────────────────────────────────────────

def _build_recommendation(level, sender, url, content, attachment, header) -> str:
    if level == "HIGH":
        parts = ["⚠️ This email shows multiple high-confidence phishing indicators. Do NOT click any links or provide credentials."]
        if sender.score >= 40:
            parts.append("The sender address is suspicious — verify through an official channel (call the organization directly).")
        if url.score >= 50:
            parts.append("Avoid opening any URLs in this email without first checking them in a link scanner.")
        if content.score >= 40:
            parts.append("The email uses social engineering (urgency/threats) to bypass your judgment — be extra cautious.")
        if attachment.score >= 40:
            parts.append("Do not open or download any attached files — they are suspicious and may contain malware.")
        if header.score >= 40:
            parts.append("Sender authentication (SPF/DKIM/DMARC) or header alignment is failing — the From address may be spoofed.")
        parts.append("Report this email to your IT/security team immediately.")
        return " ".join(parts)

    elif level == "MEDIUM":
        parts = [
            "Exercise caution with this email. While it is not definitively malicious, "
            "several indicators warrant attention. Verify the sender's identity before "
            "clicking any links or providing information. When in doubt, contact the "
            "organization through their official website or phone number."
        ]
        if header.score >= 35 and not header.auth.present:
            parts.append("The email was provided without full header/authentication data, so spoofing could not be ruled out.")
        return " ".join(parts)
    else:
        return (
            "This email appears safe based on all analyzed indicators. "
            "No immediate action is required. As always, stay vigilant — "
            "if something feels off, trust your instincts and verify with the sender."
        )
