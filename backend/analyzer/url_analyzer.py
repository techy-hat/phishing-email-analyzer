"""
url_analyzer.py — PhishGuard URL Analyzer
==========================================
Extracts all URLs from email text and scores each one for phishing risk.

Detection rules (each rule contributes points to the URL sub-score):
  [R1]  IP address used as hostname       → very high risk  (+35)
  [R2]  @ symbol in URL                  → high risk        (+30)
  [R3]  Excessive subdomains (≥4 labels) → medium risk      (+20)
  [R4]  Suspicious keyword in domain     → medium risk      (+20)
  [R5]  HTTP (not HTTPS)                 → medium risk      (+15)
  [R6]  URL shortener service            → medium risk      (+20)
  [R7]  Suspicious keyword in path       → medium risk      (+15)
  [R8]  Excessive hyphens in domain      → low-medium risk  (+10)
  [R9]  Overly long URL (>100 chars)     → low risk         (+5)

The final URL score (0–100) is the max individual URL score (capped at 100),
so a single malicious URL is enough to drive the score high.
"""

import re
from dataclasses import dataclass, field
from typing import List
from urllib.parse import urlparse


# ── Suspicious keyword lists ─────────────────────────────────────────────────

# Keywords that frequently appear in phishing domain names
SUSPICIOUS_DOMAIN_KEYWORDS = [
    "secure", "login", "verify", "account", "update", "confirm",
    "banking", "paypal", "amazon", "apple", "google", "microsoft",
    "netflix", "ebay", "support", "helpdesk", "customer", "service",
    "signin", "auth", "wallet", "password", "credential",
]

# Keywords that frequently appear in phishing URL paths
SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "verify", "update", "confirm", "account",
    "password", "reset", "credential", "authenticate", "webscr",
    "redirect", "checkout", "billing",
]

# Known URL shortener domains
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "tiny.cc", "shorte.st", "sh.st", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy",
}

# Regex to find URLs in raw text
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]]+|'          # http(s) URLs
    r'(?<!\w)www\.[^\s<>"\')\]]+',       # bare www. URLs
    re.IGNORECASE
)

# Regex to detect IPv4 as hostname
IP_HOST_PATTERN = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


@dataclass
class UrlFinding:
    """A single suspicious indicator found in a URL."""
    rule_id:  str    # e.g. "R1"
    url:      str    # The URL that triggered the finding
    detail:   str    # Human-readable description
    points:   int    # Risk points contributed


@dataclass
class UrlAnalysisResult:
    urls:          List[str] = field(default_factory=list)
    score:         int = 0              # 0–100
    findings:      List[UrlFinding] = field(default_factory=list)
    summary:       str = ""


def analyze_urls(text: str) -> UrlAnalysisResult:
    """
    Extract all URLs from `text` and evaluate each for phishing indicators.
    Returns a UrlAnalysisResult with a 0–100 score and granular findings.
    """
    result = UrlAnalysisResult()

    # ── Extract URLs ──────────────────────────────────────────────────────────
    raw_urls = URL_PATTERN.findall(text)

    # Normalise: prepend scheme to bare www. URLs, and trim trailing sentence
    # punctuation (., ,, ;, :, !, ?) that the pattern cannot distinguish from
    # characters that genuinely belong to the URL.
    urls = []
    for u in raw_urls:
        if u.lower().startswith("www."):
            u = "http://" + u
        u = u.rstrip(".,;:!?")
        if u:
            urls.append(u)

    result.urls = list(dict.fromkeys(urls))  # deduplicate, preserve order

    if not result.urls:
        result.summary = "No URLs detected in the email."
        return result

    # ── Score each URL ────────────────────────────────────────────────────────
    max_url_score = 0

    for url in result.urls:
        url_score, url_findings = _score_url(url)
        result.findings.extend(url_findings)
        max_url_score = max(max_url_score, url_score)

    result.score = min(max_url_score, 100)

    # ── Build summary ─────────────────────────────────────────────────────────
    n = len(result.urls)
    result.summary = (
        f"{n} URL{'s' if n != 1 else ''} found. "
        f"{'Suspicious indicators detected.' if result.score >= 40 else 'No major URL threats detected.'}"
    )

    return result


def _score_url(url: str):
    """
    Score a single URL against all detection rules.
    Returns (score: int, findings: List[UrlFinding]).
    """
    findings: List[UrlFinding] = []
    total = 0

    try:
        parsed = urlparse(url)
    except Exception:
        return 0, findings

    hostname = (parsed.hostname or "").lower()
    path     = (parsed.path or "").lower()
    scheme   = (parsed.scheme or "").lower()

    # [R1] IP address as hostname
    if IP_HOST_PATTERN.match(hostname):
        pts = 35
        total += pts
        findings.append(UrlFinding(
            rule_id="R1",
            url=url,
            detail=f"URL uses a raw IP address ({hostname}) instead of a domain name — a common phishing tactic to evade domain-based detection.",
            points=pts
        ))

    # [R2] @ symbol in URL authority (tricks browsers into ignoring the real domain)
    # Only the authority/host part matters: an '@' in the path or query string
    # (e.g. ?user=joe@example.com) is legitimate and must not be flagged.
    if "@" in (parsed.netloc or ""):
        pts = 30
        total += pts
        findings.append(UrlFinding(
            rule_id="R2",
            url=url,
            detail=f"URL contains '@' symbol. Everything before '@' is ignored by the browser; the actual destination is '{hostname}'.",
            points=pts
        ))

    # [R3] Excessive subdomains (4+ dot-separated labels)
    labels = hostname.split(".")
    if len(labels) >= 4:
        pts = 20
        total += pts
        findings.append(UrlFinding(
            rule_id="R3",
            url=url,
            detail=f"URL has {len(labels)} subdomain levels ({hostname}). Phishing sites often use deep subdomains to disguise the real domain.",
            points=pts
        ))

    # [R4] Suspicious keywords in domain
    domain_hits = [kw for kw in SUSPICIOUS_DOMAIN_KEYWORDS if kw in hostname]
    if domain_hits:
        pts = 20
        total += pts
        findings.append(UrlFinding(
            rule_id="R4",
            url=url,
            detail=f"Domain contains suspicious keywords: {', '.join(domain_hits)}. These are frequently used in phishing domains.",
            points=pts
        ))

    # [R5] HTTP instead of HTTPS
    if scheme == "http":
        pts = 15
        total += pts
        findings.append(UrlFinding(
            rule_id="R5",
            url=url,
            detail="URL uses HTTP (unencrypted). Legitimate credential or banking pages always use HTTPS.",
            points=pts
        ))

    # [R6] URL shortener
    # Check registered domain (last two labels)
    registered_domain = ".".join(labels[-2:]) if len(labels) >= 2 else hostname
    if registered_domain in URL_SHORTENERS:
        pts = 20
        total += pts
        findings.append(UrlFinding(
            rule_id="R6",
            url=url,
            detail=f"URL uses a shortening service ({registered_domain}), which hides the actual destination.",
            points=pts
        ))

    # [R7] Suspicious keywords in path
    path_hits = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in path]
    if path_hits:
        pts = 15
        total += pts
        findings.append(UrlFinding(
            rule_id="R7",
            url=url,
            detail=f"URL path contains suspicious keywords: {', '.join(path_hits)}.",
            points=pts
        ))

    # [R8] Excessive hyphens in hostname (e.g. secure-login-paypal-verify.com)
    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        pts = 10
        total += pts
        findings.append(UrlFinding(
            rule_id="R8",
            url=url,
            detail=f"Domain has {hyphen_count} hyphens ({hostname}). Excessive hyphens are common in phishing domains.",
            points=pts
        ))

    # [R9] Very long URL (over 100 chars)
    if len(url) > 100:
        pts = 5
        total += pts
        findings.append(UrlFinding(
            rule_id="R9",
            url=url,
            detail=f"URL is unusually long ({len(url)} characters), possibly to obscure the true destination.",
            points=pts
        ))

    return min(total, 100), findings
