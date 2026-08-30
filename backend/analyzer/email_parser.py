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
