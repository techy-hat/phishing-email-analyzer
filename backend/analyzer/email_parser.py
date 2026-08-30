"""
email_parser.py — PhishGuard Email Parser
==========================================
Responsible for extracting structured fields from raw email text.

Extracts:
  - from_address: sender email address
  - from_name:    display name (if present)
  - from_domain:  domain part of the sender address
  - subject:      email subject line
  - body:         plain-text body of the email
  - headers_raw:  raw header block for advanced inspection

No external libraries required; uses only the Python stdlib email module.
"""

import email
import re
from dataclasses import dataclass, field
from email.header import decode_header, make_header
from email.utils import parseaddr
from typing import Any, Dict, List, Optional


@dataclass
class ParsedEmail:
    from_address: Optional[str] = None   # e.g. "support@paypa1.com"
    from_name:    Optional[str] = None   # e.g. "PayPal Support"
    from_domain:  Optional[str] = None   # e.g. "paypa1.com"
    subject:      Optional[str] = None
    body:         str = ""
    headers_raw:  str = ""
    headers:      Dict[str, str] = field(default_factory=dict)  # lowercase -> raw value
    to_address:   Optional[str] = None
    reply_to:     Optional[str] = None
    return_path:  Optional[str] = None
    message_id:   Optional[str] = None
    date:         Optional[str] = None
    authentication_results: str = ""
    spf:          Optional[str] = None   # e.g. "pass" | "fail" | None
    dkim:         Optional[str] = None   # e.g. "pass" | "fail" | None
    dmarc:        Optional[str] = None   # e.g. "pass" | "fail" | None
    has_headers:  bool = False           # True if input had a structured header block
    attachments:  List[Dict[str, Any]] = field(default_factory=list)


def parse_email(raw: str) -> ParsedEmail:
    """
    Parse a raw email string (RFC-2822 or plain text body) into a ParsedEmail.

    Strategy:
      1. Try stdlib email.message_from_string — works for proper .eml format.
      2. Fall back to simple regex extraction if the input looks like a plain
         email paste (no MIME structure).
    """
    parsed = ParsedEmail()

    # ── Try stdlib parser first ───────────────────────────────────────────────
    msg = email.message_from_string(raw)

    # Extract From header
    from_header = msg.get("From", "")
    if from_header:
        parsed.from_address, parsed.from_name = _parse_from_header(from_header)
        if parsed.from_address:
            parsed.from_domain = parsed.from_address.split("@")[-1].lower().strip()

    subject = msg.get("Subject", None)
    parsed.subject = _decode_words(subject) if subject else None

    # Collect headers as raw string for inspection
    parsed.headers_raw = "\n".join(
        f"{k}: {v}" for k, v in msg.items()
    )

    # Build a lowercase-keyed headers dict for downstream analyzers
    for k, v in msg.items():
        parsed.headers.setdefault(k.lower(), v)

    parsed.has_headers = bool(list(msg.items()))

    # ── Additional header fields ───────────────────────────────────────────────
    parsed.to_address, _ = _parse_from_header(msg.get("To", ""))
    parsed.reply_to, _   = _parse_from_header(msg.get("Reply-To", ""))
    parsed.return_path, _ = _parse_from_header(msg.get("Return-Path", ""))
    parsed.message_id = msg.get("Message-ID") or None
    parsed.date       = msg.get("Date") or None
    parsed.authentication_results = msg.get("Authentication-Results", "")

    # ── Parse SPF / DKIM / DMARC from Authentication-Results / headers ─────────
    auth_all = (
        msg.get("Authentication-Results", "") + "\n" +
        msg.get("Received-SPF", "") + "\n" +
        msg.get("DKIM-Signature", "")
    )
    parsed.spf   = _parse_auth_mechanism(auth_all, ("spf", "smtp.mailfrom"))
    parsed.dkim  = _parse_auth_mechanism(auth_all, "dkim")
    parsed.dmarc = _parse_auth_mechanism(auth_all, "dmarc")

    # Extract body
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    parsed.body += payload.decode("utf-8", errors="replace")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            parsed.body = payload.decode("utf-8", errors="replace")
        else:
            # Plain string payload (no encoding)
            raw_payload = msg.get_payload()
            if isinstance(raw_payload, str):
                parsed.body = raw_payload

    # Extract attachment metadata (non-inline non-text parts)
    parsed.attachments = _extract_attachments(msg)

    # ── Fallback: plain-text email paste ─────────────────────────────────────
    # If the stdlib parser found no From address, try regex on the raw text.
    if not parsed.from_address:
        parsed.from_address, parsed.from_name = _regex_extract_from(raw)
        if parsed.from_address:
            parsed.from_domain = parsed.from_address.split("@")[-1].lower().strip()

    if not parsed.subject:
        parsed.subject = _regex_extract_subject(raw)

    # If body is empty after all that, treat the full raw text as the body
    if not parsed.body.strip():
        parsed.body = raw

    return parsed


# ── Helpers ──────────────────────────────────────────────────────────────────

def _parse_from_header(header: str):
    """
    Parse 'Display Name <user@domain.com>' or 'user@domain.com'.
    Returns (address, display_name). RFC 2047 encoded words in the
    display name (e.g. '=?utf-8?q?Hi?=') are decoded.
    """
    try:
        name, addr = parseaddr(header)
    except Exception:
        return None, None

    if addr:
        if name:
            name = _decode_words(name).strip()
        return addr.lower(), name or None

    return None, None


def _decode_words(value: str) -> str:
    """
    Decode RFC 2047 encoded words (e.g. '=?utf-8?q?foo=20bar?=') inside a
    single header value. Returns the decoded text, or the original value if
    decoding fails (malformed header)."""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _regex_extract_from(text: str):
    """Extract From: line via regex for plain-text pastes."""
    match = re.search(r'^From:\s*(.+)$', text, re.IGNORECASE | re.MULTILINE)
    if match:
        return _parse_from_header(match.group(1))
    return None, None


def _regex_extract_subject(text: str):
    """Extract Subject: line via regex for plain-text pastes."""
    match = re.search(r'^Subject:\s*(.+)$', text, re.IGNORECASE | re.MULTILINE)
    if match:
        return _decode_words(match.group(1).strip())
    return None


def _extract_attachments(msg) -> List[Dict[str, Any]]:
    """
    Walk the message tree and collect non-text attachment metadata.
    Returns a list of dicts: {"filename", "content_type", "size"}.
    """
    attachments: List[Dict[str, Any]] = []

    for part in msg.walk():
        # Skip the main body text parts
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        if content_type in ("text/plain", "text/html"):
            # Inline alternative text without a filename is not an attachment
            if not part.get_filename():
                continue

        filename = part.get_filename()
        if not filename:
            continue

        # Decode RFC-2231 / quoted-printable encoded filename if present
        try:
            from email.header import decode_header
            decoded = decode_header(filename)
            filename = "".join(
                t.decode(c or "utf-8", errors="replace") if isinstance(t, bytes) else t
                for t, c in decoded
            )
        except Exception:
            pass

        payload = part.get_payload(decode=True)
        size = len(payload) if payload else 0

        attachments.append({
            "filename":     filename,
            "content_type": content_type,
            "size":         size,
        })

    return attachments


def _parse_auth_mechanism(text: str, mechanisms) -> Optional[str]:
    """
    Extract the pass/fail/skip result for an auth mechanism (SPF/DKIM/DMARC)
    from an Authentication-Results / Received-SPF / DKIM-Signature block.

    `mechanisms` may be a single string or a tuple of names to look for.
    Looks for a pattern like `spf=pass` (optionally with a detail footer).
    Returns None when unresolved or irrelevant.
    """
    if not text:
        return None
    if isinstance(mechanisms, str):
        mechanisms = (mechanisms,)
    m_re = "|".join(re.escape(m) for m in mechanisms)
    # Format in Authentication-Results: spf=pass (detail) ... or spf "pass"
    match = re.search(
        re.compile(rf"(?:{m_re})\s*=\s*[\"']?([A-Za-z-]+)", re.IGNORECASE), text
    )
    if match:
        return match.group(1).lower()
    # Received-SPF / DKIM signature alternate forms
    match2 = re.search(
        re.compile(rf"(?:{m_re}) \(([^)]*?)\s*(\bpass\b|\bfail\b|\bneutral\b|\bnone\b|\bsoftfail\b)", re.IGNORECASE),
        text,
    )
    if match2:
        return match2.group(2).lower()
    return None
