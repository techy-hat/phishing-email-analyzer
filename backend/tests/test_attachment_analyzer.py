"""Tests for the attachment analyzer module."""

import pytest

from analyzer.attachment_analyzer import analyze_attachments


def test_no_attachments():
    result = analyze_attachments([])
    assert result.score == 0
    assert result.findings == []
    assert "No attachments" in result.summary


def test_dangerous_extension():
    result = analyze_attachments([{"filename": "invoice.exe", "content_type": "application/octet-stream", "size": 100}])
    assert result.score >= 35
    assert any(f.rule == "R-A1" for f in result.findings)


def test_macro_office_document():
    result = analyze_attachments([{"filename": "report.docm", "content_type": "application/vnd.ms-word", "size": 500}])
    assert result.score >= 35
    assert any(f.rule == "R-A2" for f in result.findings)


def test_double_extension():
    result = analyze_attachments([{"filename": "invoice.pdf.exe", "content_type": "application/octet-stream", "size": 200}])
    # Double extension is also a dangerous ext, so both rules fire
    assert any(f.rule == "R-A3" for f in result.findings)
    assert any(f.rule == "R-A1" for f in result.findings)


def test_suspicious_mime():
    result = analyze_attachments([{"filename": "setup.msi", "content_type": "application/x-msdownload", "size": 300}])
    assert any(f.rule == "R-A4" for f in result.findings)


def test_archive():
    result = analyze_attachments([{"filename": "documents.zip", "content_type": "application/zip", "size": 1000}])
    assert any(f.rule == "R-A5" for f in result.findings)


def test_suspicious_filename_keyword():
    result = analyze_attachments([{"filename": "Invoice_2026.pdf", "content_type": "application/pdf", "size": 400}])
    # Plain PDF is safe, but 'invoice' keyword flags low risk
    assert any(f.rule == "R-A6" for f in result.findings)
    assert result.score < 35


def test_benign_attachment_zero():
    result = analyze_attachments([{"filename": "meeting_notes.txt", "content_type": "text/plain", "size": 50}])
    assert result.score == 0
    assert result.findings == []


def test_worst_attachment_wins():
    attachments = [
        {"filename": "meeting.txt", "content_type": "text/plain", "size": 50},
        {"filename": "malware.exe", "content_type": "application/octet-stream", "size": 999},
    ]
    result = analyze_attachments(attachments)
    assert result.score >= 35
