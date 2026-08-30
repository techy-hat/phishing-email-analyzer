"""
attachment_analyzer.py — PhishGuard Attachment Analyzer
=========================================================
Scores email attachments for phishing / malware risk.

Input is a list of attachment metadata dicts:
    [{"filename": str, "content_type": str, "size": int}, ...]

Detection rules (each rule contributes points to the attachment sub-score):
  [R-A1] Dangerous executable extension      → very high risk  (+35)
  [R-A2] Macro-enabled Office document       → very high risk  (+35)
  [R-A3] Double extension (e.g. x.pdf.exe)   → high risk       (+30)
  [R-A4] Suspicious MIME type                → medium risk     (+20)
  [R-A5] Archive containing executables      → medium risk     (+20)
  [R-A6] Suspicious filename keyword         → low risk        (+10)

The final attachment score (0–100) is the max individual attachment score
(capped at 100), mirroring the URL analyzer's "worst item wins" approach.
"""

import os
from dataclasses import dataclass, field
from typing import List, Dict, Any


# ── Dangerous categories ──────────────────────────────────────────────────────

# Directly executable / weaponizable file extensions
DANGEROUS_EXTENSIONS = {
    "exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "pif",
    "msi", "msp", "lnk", "hta", "com", "cpl", "wsf", "wsh", "ps1",
    "reg", "scr",
}

# Macro-capable Office documents — frequently used for macro malware
MACRO_EXTENSIONS = {
    "docm", "xlsm", "pptm", "doc", "xls", "ppt", "dotm", "xlam", "ppam",
}

# Archives that could carry malicious payloads
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "tar", "gz", "jar", "iso"}

# MIME types strongly associated with malware delivery
SUSPICIOUS_MIME = {
    "application/x-msdownload",
    "application/x-msi",
    "application/vnd.ms-excel",
    "application/vnd.ms-office",
    "application/x-httpd-php",
    "application/x-sh",
}

# Keywords in filenames that lure users into opening malicious attachments
SUSPICIOUS_NAME_KEYWORDS = [
    "invoice", "payment", "resume", "password", "document", "statement",
    "receipt", "order", "signature", "scan", "details", "0000",
    "account", "update", "confirm", "report", "contract", "bank",
]


@dataclass
class AttachmentFinding:
    """A single suspicious indicator found in an attachment."""
    rule:     str     # e.g. "R-A1"
    filename: str     # The attachment filename
    detail:   str     # Human-readable description
    points:   int     # Risk points contributed


@dataclass
class AttachmentAnalysisResult:
    attachments:  List[Dict[str, Any]] = field(default_factory=list)
    score:        int = 0              # 0–100
    findings:     List[AttachmentFinding] = field(default_factory=list)
    summary:      str = ""


def analyze_attachments(attachments: List[Dict[str, Any]]) -> AttachmentAnalysisResult:
    """
    Score a list of attachment metadata dicts for phishing / malware risk.
    Returns an AttachmentAnalysisResult with a 0–100 score and findings.
    """
    result = AttachmentAnalysisResult(attachments=attachments)

    if not attachments:
        result.summary = "No attachments found in the email."
        return result

    max_score = 0
    for att in attachments:
        att_score, att_findings = _score_attachment(att)
        result.findings.extend(att_findings)
        max_score = max(max_score, att_score)

    result.score = min(max_score, 100)

    n = len(attachments)
    result.summary = (
        f"{n} attachment{'s' if n != 1 else ''} found. "
        f"{'Suspicious attachment indicators detected.' if result.score >= 40 else 'No major attachment threats detected.'}"
    )

    return result


def _score_attachment(att: Dict[str, Any]) -> tuple:
    """Score a single attachment metadata dict against all detection rules."""
    findings: List[AttachmentFinding] = []
    total = 0

    filename = (att.get("filename") or "").strip()
    content_type = (att.get("content_type") or "").lower()

    # Lowercased base name, split into parts
    lower = filename.lower()
    name_no_ext = lower.rsplit(".", 1)[0] if "." in lower else lower

    # Determine extension(s) — handle multi-dot names like "invoice.pdf.exe"
    parts = lower.split(".")
    ext = parts[-1] if len(parts) > 1 else ""

    # [R-A3] Double extension — check for a second trailing extension
    double_ext = ""
    if len(parts) >= 2:
        double_ext = parts[-2]
    has_double_ext = ext in (DANGEROUS_EXTENSIONS | MACRO_EXTENSIONS | ARCHIVE_EXTENSIONS) and \
        double_ext in {"pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "jpeg",
                       "png", "gif", "zip", "rtf", "msg", "eml"}

    # [R-A1] Dangerous executable extension
    if ext in DANGEROUS_EXTENSIONS:
        pts = 35
        total += pts
        findings.append(AttachmentFinding(
            rule="R-A1",
            filename=filename,
            detail=f"Attachment has a directly dangerous file extension (.{ext}), commonly used to deliver malware.",
            points=pts
        ))

    # [R-A2] Macro-enabled Office document
    elif ext in MACRO_EXTENSIONS:
        pts = 35
        total += pts
        findings.append(AttachmentFinding(
            rule="R-A2",
            filename=filename,
            detail=f"Attachment is a macro-capable Office document (.{ext}) — a frequent malware vector.",
            points=pts
        ))

    # [R-A3] Double extension (e.g. invoice.pdf.exe)
    if has_double_ext:
        pts = 30
        total += pts
        findings.append(AttachmentFinding(
            rule="R-A3",
            filename=filename,
            detail=f"Attachment uses a double extension ({double_ext}.{ext}) — a classic trick to disguise malware as a safe file type.",
            points=pts
        ))

    # [R-A4] Suspicious MIME type
    if content_type in SUSPICIOUS_MIME:
        pts = 20
        total += pts
        findings.append(AttachmentFinding(
            rule="R-A4",
            filename=filename,
            detail=f"Attachment has a suspicious MIME type ({content_type}) commonly associated with malware delivery.",
            points=pts
        ))

    # [R-A5] Archive containing executables (self-extracting style names)
    if ext in ARCHIVE_EXTENSIONS:
        pts = 20
        total += pts
        findings.append(AttachmentFinding(
            rule="R-A5",
            filename=filename,
            detail=f"Attachment is an archive (.{ext}) that could contain a malicious payload. Archives are often used to bypass attachment filters.",
            points=pts
        ))

    # [R-A6] Suspicious filename keyword
    kw_hits = [kw for kw in SUSPICIOUS_NAME_KEYWORDS if kw in lower]
    if kw_hits:
        pts = 10
        total += pts
        findings.append(AttachmentFinding(
            rule="R-A6",
            filename=filename,
            detail=f"Attachment filename contains suspicious lure keywords: {', '.join(kw_hits)}.",
            points=pts
        ))

    return min(total, 100), findings
