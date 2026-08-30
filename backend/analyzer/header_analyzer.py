"""
header_analyzer.py — PhishGuard Header & Authentication Analyzer
================================================================
Scores the email headers (From / To / Reply-To / Return-Path alignment and
SPF / DKIM / DMARC authentication results) as a distinct risk layer.

This layer treats authentication failures and header inconsistencies as RISK
SIGNALS, not proof of phishing — legitimate mail can fail auth for many
benign reasons (forwarding, mailing lists, misconfiguration).

Detection rules (each contributes points to the header sub-score):
  [H1] Reply-To points to a different domain than From   → +30
  [H2] Reply-To is a free provider while From is a brand → +25
  [H3] Return-Path domain differs from From domain       → +15
  [H4] DMARC fails / marked suspicious                    → +25
  [H5] SPF fails / hardfail                               → +20
  [H6] DKIM fails                                         → +15
  [H7] Authentication results are missing entirely (no .eml headers) → +10

The final header score is capped at 100.
"""

from dataclasses import dataclass, field
from typing import List, Optional

from .email_parser import ParsedEmail


@dataclass
class HeaderFinding:
    label:   str
    detail:  str
    points:  int
    severity: str  # "HIGH" | "MEDIUM" | "LOW"


@dataclass
class AuthStatus:
    spf:   Optional[str] = None
    dkim:  Optional[str] = None
    dmarc: Optional[str] = None
    present: bool = False   # whether any auth evidence was found


@dataclass
class HeaderAnalysisResult:
    score:        int = 0
    findings:     List[HeaderFinding] = field(default_factory=list)
    auth:         AuthStatus = field(default_factory=AuthStatus)
    reply_to:     Optional[str] = None
    return_path:  Optional[str] = None
    has_headers:  bool = False
    summary:      str = ""


FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "mail.com", "yandex.com",
    "gmx.com", "icloud.com", "live.com",
}


def _domain(addr: Optional[str]) -> Optional[str]:
    if not addr:
        return None
    if "@" in addr:
        return addr.split("@")[-1].lower().strip()
    return None


def analyze_headers(parsed: ParsedEmail) -> HeaderAnalysisResult:
    """Score email headers and authentication results for risk signals."""
    result = HeaderAnalysisResult(
        reply_to=parsed.reply_to,
        return_path=parsed.return_path,
        has_headers=parsed.has_headers,
        auth=AuthStatus(
            spf=parsed.spf, dkim=parsed.dkim,
            dmarc=parsed.dmarc, present=(parsed.has_headers and bool(
                parsed.authentication_results or parsed.spf or parsed.dkim or parsed.dmarc
            )),
        ),
    )

    from_dom   = _domain(parsed.from_address)
    reply_dom  = _domain(parsed.reply_to)
    return_dom = _domain(parsed.return_path)

    total = 0

    def _add(label, detail, pts, sev):
        nonlocal total
        total += pts
        result.findings.append(HeaderFinding(label, detail, pts, sev))

    # [H1] Reply-To domain differs from From domain
    if reply_dom and from_dom and reply_dom != from_dom:
        _add(
            "Reply-To Domain Mismatch",
            f"The Reply-To address ({parsed.reply_to}) uses a different domain "
            f"({reply_dom}) than the From address ({from_dom}). Replies to a phishing "
            "email can be routed to the attacker.",
            30, "HIGH",
        )
    # [H2] Reply-To is a free provider while From claims an organizational domain
    elif reply_dom and from_dom and reply_dom in FREE_EMAIL_PROVIDERS and from_dom not in FREE_EMAIL_PROVIDERS:
        _add(
            "Reply-To Uses Free Email Provider",
            f"The Reply-To address routes replies to a free provider ({reply_dom}) "
            "even though the From domain appears to be organizational. "
            "This is a common trick to collect replies outside monitoring.",
            25, "MEDIUM",
        )

    # [H3] Return-Path domain differs from From domain
    if return_dom and from_dom and return_dom != from_dom:
        _add(
            "Return-Path Domain Mismatch",
            f"The Return-Path/Envelope domain ({return_dom}) differs from the From "
            f"domain ({from_dom}). Mismatched envelope vs. header sender can indicate "
            "spoofed mail.",
            15, "MEDIUM",
        )

    # [H4] DMARC
    if parsed.dmarc and parsed.dmarc in ("fail", "neutral", "softfail", "none"):
        _add(
            "DMARC Authentication Failed",
            f"DMARC result is '{parsed.dmarc.upper()}'. The domain's policy is not "
            "aligned or not satisfied, so the 'From' address could have been spoofed.",
            25, "HIGH",
        )

    # [H5] SPF
    if parsed.spf and parsed.spf in ("fail", "softfail"):
        _add(
            "SPF Authentication Failed",
            f"SPF result is '{parsed.spf.upper()}'. The sending server was not "
            "authorized by the domain's DNS to send mail.",
            20, "MEDIUM",
        )

    # [H6] DKIM
    if parsed.dkim and parsed.dkim == "fail":
        _add(
            "DKIM Signature Failed",
            "The DKIM signature failed to validate, meaning the message may have "
            "been tampered with or not signed by the claimed domain.",
            15, "MEDIUM",
        )

    # [H7] No structured headers / no authentication evidence present
    if not parsed.has_headers or not (parsed.authentication_results or parsed.spf or parsed.dkim or parsed.dmarc):
        _add(
            "No Authentication Headers Found",
            "No SPF/DKIM/DMARC authentication results or structured headers were "
            "found. This typically means the email was pasted without its full "
            "header block, so spoofing cannot be ruled out. Treat as a data gap.",
            10, "LOW",
        )

    result.score = min(total, 100)

    if result.findings:
        result.summary = f"Header/auth layer flagged {len(result.findings)} issue(s)."
    else:
        result.summary = "Header and authentication indicators appear aligned and healthy."

    return result
