"""
content_analyzer.py — PhishGuard Content Analyzer
===================================================
Detects social-engineering and phishing patterns in the email body and subject.

Detection categories and their rules:

  [C1]  URGENCY LANGUAGE
        Phrases that create artificial time pressure.
        Examples: "urgent", "act immediately", "within 24 hours", "account suspended"

  [C2]  CREDENTIAL / LOGIN REQUESTS
        Asking the user to enter passwords or sensitive information.
        Examples: "verify your password", "confirm your credentials", "login to"

  [C3]  THREAT / FEAR LANGUAGE
        Intimidation tactics to force compliance.
        Examples: "your account will be terminated", "legal action", "unauthorized access"

  [C4]  FINANCIAL / REWARD BAIT
        Prize, lottery, or money-transfer lures.
        Examples: "you have won", "claim your prize", "transfer funds", "inheritance"

Each matched pattern contributes points to the content sub-score.
The final content score is capped at 100.
"""

import re
from dataclasses import dataclass, field
from typing import List, Tuple


# ── Pattern definitions ───────────────────────────────────────────────────────
# Each entry: (pattern_text, points, category, friendly_label)
# Patterns use re.IGNORECASE and re.search() semantics (substring match).

_PATTERNS: List[Tuple[str, int, str, str]] = [

    # ── [C1] Urgency ──────────────────────────────────────────────────────────
    (r'\burgent\b',                   12, "C1", "Urgency keyword: 'urgent'"),
    (r'\bimmediately\b',              10, "C1", "Urgency keyword: 'immediately'"),
    (r'\bact now\b',                  10, "C1", "Urgency phrase: 'act now'"),
    (r'\bwithin \d+ hours?\b',        12, "C1", "Time-pressure phrase: 'within N hours'"),
    (r'\bwithin \d+ minutes?\b',      12, "C1", "Time-pressure phrase: 'within N minutes'"),
    (r'\bwithin \d+ days?\b',         10, "C1", "Time-pressure phrase: 'within N days'"),
    (r'\baccount.{0,20}suspend',      15, "C1", "Account suspension threat"),
    (r'\baccount.{0,20}terminat',     15, "C1", "Account termination threat"),
    (r'\baccount.{0,20}locked?\b',    12, "C1", "Account locked threat"),
    (r'\baccount.{0,20}disabled?\b',  12, "C1", "Account disabled threat"),
    (r'\bexpire[sd]?\b',              8,  "C1", "Expiry urgency keyword"),
    (r'\bfinal notice\b',             12, "C1", "Final notice phrase"),
    (r'\blast chance\b',              10, "C1", "Last chance phrase"),
    (r'\btime.{0,10}sensitive\b',     10, "C1", "Time-sensitive phrase"),
    (r'\bdeadline\b',                 8,  "C1", "Deadline urgency keyword"),
    (r'\bdo not ignore\b',            10, "C1", "'Do not ignore' phrase"),
    (r'\brespond immediately\b',      12, "C1", "'Respond immediately' phrase"),
    (r'\bfailure to\b',               8,  "C1", "'Failure to' warning phrase"),

    # ── [C2] Credential requests ──────────────────────────────────────────────
    (r'\bverify.{0,20}(password|credentials?|account|identity)\b',
                                      20, "C2", "Credential verification request"),
    (r'\bconfirm.{0,20}(password|credentials?|account|identity)\b',
                                      20, "C2", "Credential confirmation request"),
    (r'\bupdate.{0,20}(password|credentials?|payment|billing)\b',
                                      18, "C2", "Credential update request"),
    (r'\b(enter|provide|submit).{0,20}(password|credentials?|pin|ssn|social security)\b',
                                      22, "C2", "Direct credential solicitation"),
    (r'\blog.{0,5}in\b',              8,  "C2", "'Login' prompt"),
    (r'\bsign in\b',                  8,  "C2", "'Sign in' prompt"),
    (r'\bclick.{0,20}(here|link|button).{0,20}(verify|confirm|update|login)\b',
                                      15, "C2", "Click-to-verify link prompt"),
    (r'\byour (password|pin|credentials?)\b',
                                      12, "C2", "Personal credential reference"),

    # ── [C3] Threat / fear language ───────────────────────────────────────────
    (r'\bunauthorized.{0,20}access\b',15, "C3", "Unauthorized access claim"),
    (r'\bsuspicious.{0,20}(activity|login|access)\b',
                                      15, "C3", "Suspicious activity claim"),
    (r'\blegal.{0,10}action\b',       18, "C3", "Legal action threat"),
    (r'\blaw enforcement\b',          18, "C3", "Law enforcement threat"),
    (r'\byour account has been (hacked|compromised|breached)\b',
                                      20, "C3", "Account compromise claim"),
    (r'\bwe detected\b',              8,  "C3", "'We detected' fear-trigger"),
    (r'\babnormal activity\b',        12, "C3", "Abnormal activity claim"),
    (r'\bsecurity (alert|warning|breach|incident)\b',
                                      12, "C3", "Security alert language"),
    (r'\brisk of (losing|termination|suspension)\b',
                                      15, "C3", "Risk-of-loss threat"),

    # ── [C4] Financial / reward bait ─────────────────────────────────────────
    (r'\byou have (won|been selected)\b',
                                      20, "C4", "Prize or selection lure"),
    (r'\bclaim.{0,20}(prize|reward|gift|money|refund)\b',
                                      18, "C4", "Prize claim lure"),
    (r'\b(lottery|sweepstake)\b',     20, "C4", "Lottery/sweepstake lure"),
    (r'\binheritance\b',              20, "C4", "Inheritance scam indicator"),
    (r'\btransfer.{0,20}(funds?|money|million|thousand)\b',
                                      20, "C4", "Fund transfer request"),
    (r'\b(bitcoin|crypto|wallet).{0,30}(send|transfer|invest)\b',
                                      18, "C4", "Cryptocurrency scam indicator"),
    (r'\brefund\b',                   8,  "C4", "Refund bait keyword"),
    (r'\bprize\b',                    10, "C4", "Prize bait keyword"),
    (r'\bfree (gift|offer|access|trial)\b',
                                      10, "C4", "Free offer lure"),
    (r'\bcongratulations\b',          8,  "C4", "Congratulations lure"),
]

# Pre-compile all patterns for performance
_COMPILED = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), pts, cat, label)
    for p, pts, cat, label in _PATTERNS
]

# Category labels for reporting
_CATEGORY_NAMES = {
    "C1": "Urgency / Time Pressure",
    "C2": "Credential / Login Request",
    "C3": "Threat / Fear Language",
    "C4": "Financial / Reward Bait",
}


@dataclass
class ContentFinding:
    """A single social-engineering pattern match."""
    category:    str    # e.g. "C1"
    label:       str    # Human-readable rule label
    points:      int    # Risk points contributed
    excerpt:     str    # Short excerpt from the email showing the match


@dataclass
class ContentAnalysisResult:
    score:          int = 0              # 0–100
    findings:       List[ContentFinding] = field(default_factory=list)
    categories_hit: List[str] = field(default_factory=list)  # unique category IDs
    summary:        str = ""


def analyze_content(subject: str, body: str) -> ContentAnalysisResult:
    """
    Scan the email subject and body for phishing/social-engineering patterns.
    Returns a ContentAnalysisResult with a 0–100 score and detailed findings.

    The subject is scanned with 2× weight since it is the first (and often
    only) text a recipient reads. A pattern matched in both the subject and
    the body is reported once, attributed to the subject.
    """
    result = ContentAnalysisResult()

    total_points = 0
    seen_labels: set = set()   # avoid duplicate findings from the same pattern

    def scan(text: str, weight: int) -> None:
        nonlocal total_points
        if not text:
            return
        for regex, pts, cat, label in _COMPILED:
            match = regex.search(text)
            if match and label not in seen_labels:
                seen_labels.add(label)

                # Extract a short excerpt (±40 chars around the match)
                start = max(0, match.start() - 40)
                end   = min(len(text), match.end() + 40)
                excerpt = "…" + text[start:end].replace("\n", " ").strip() + "…"

                weighted = pts * weight
                result.findings.append(ContentFinding(
                    category=cat,
                    label=label,
                    points=weighted,
                    excerpt=excerpt,
                ))
                total_points += weighted

    # Scan the subject first at double weight, then the body at single weight.
    scan(subject or "", 2)
    scan(body or "", 1)

    result.score = min(total_points, 100)

    # Unique categories hit
    result.categories_hit = list(dict.fromkeys(
        f.category for f in result.findings
    ))

    # Summary
    cat_names = [_CATEGORY_NAMES[c] for c in result.categories_hit if c in _CATEGORY_NAMES]
    if cat_names:
        result.summary = f"Detected {len(result.findings)} social-engineering indicators across: {'; '.join(cat_names)}."
    else:
        result.summary = "No social-engineering patterns detected in email content."

    return result
