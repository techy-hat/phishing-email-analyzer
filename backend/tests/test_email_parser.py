"""Tests for the email parser module."""

import pytest

from analyzer.email_parser import parse_email


def test_parse_full_headers_rfc2822():
    raw = (
        "From: PayPal Support <security@paypa1-site.com>\n"
        "To: user@example.com\n"
        "Subject: Urgent: account suspended\n"
        "Date: Mon, 1 Jan 2026 00:00:00 +0000\n"
        "\n"
        "Dear user, click here to verify your account.\n"
    )
    p = parse_email(raw)
    assert p.from_address == "security@paypa1-site.com"
    assert p.from_name == "PayPal Support"
    assert p.from_domain == "paypa1-site.com"
    assert p.subject == "Urgent: account suspended"
    assert "verify your account" in p.body


def test_parse_plain_text_paste_no_headers():
    raw = (
        "Hi there,\n"
        "Please review the attached document and confirm at your earliest convenience.\n"
    )
    p = parse_email(raw)
    # No From -> no domain
    assert p.from_address is None
    assert p.from_domain is None
    # Subject absent
    assert p.subject is None
    # Body falls back to the full text
    assert "Please review" in p.body


def test_parse_regex_extracts_from_and_subject_from_plain_paste():
    raw = (
        "From: security@fake-login.com\n"
        "Subject: Your invoice\n"
        "\n"
        "Body text here.\n"
    )
    p = parse_email(raw)
    assert p.from_address == "security@fake-login.com"
    assert p.from_domain == "fake-login.com"
    assert p.subject == "Your invoice"


def test_from_domain_lowercased():
    raw = "From: Foo <Admin@Example.COM>\n\nHello\n"
    p = parse_email(raw)
    assert p.from_domain == "example.com"


def test_parse_multipart_email_attachments():
    raw = (
        "From: sender@example.com\n"
        "To: victim@example.com\n"
        "Subject: Invoice\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=\"BOUNDARY1\"\n"
        "\n"
        "--BOUNDARY1\n"
        "Content-Type: text/plain\n"
        "\n"
        "Please see the attached invoice.\n"
        "--BOUNDARY1\n"
        "Content-Type: text/plain; name=\"invoice.txt\"\n"
        "Content-Disposition: attachment; filename=\"invoice.txt\"\n"
        "\n"
        "fake invoice content\n"
        "--BOUNDARY1--\n"
    )
    p = parse_email(raw)
    # We expect one attachment extracted
    assert len(p.attachments) == 1
    att = p.attachments[0]
    assert att["filename"] == "invoice.txt"
    assert att["content_type"] == "text/plain"
    assert att["size"] > 0


def test_no_attachments_when_single_part():
    raw = "From: a@b.com\n\nJust a plain text email, no attachments.\n"
    p = parse_email(raw)
    assert p.attachments == []
