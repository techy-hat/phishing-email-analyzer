"""Tests for the risk engine and risk aggregation."""

import pytest

from analyzer.attachment_analyzer import AttachmentAnalysisResult, AttachmentFinding
from analyzer.content_analyzer import ContentAnalysisResult, ContentFinding
from analyzer.email_parser import parse_email
from analyzer.risk_engine import (
    SenderAnalysisResult,
    SenderFinding,
    analyze_sender,
    build_risk_result,
)
from analyzer.url_analyzer import UrlAnalysisResult, UrlFinding


def _sender(score, findings=None):
    return SenderAnalysisResult(score=score, findings=findings or [], summary="")


def _url(score, findings=None, urls=None):
    return UrlAnalysisResult(urls=urls or [], score=score, findings=findings or [], summary="")


def _content(score, findings=None):
    return ContentAnalysisResult(score=score, findings=findings or [], categories_hit=[], summary="")


def _attachment(score, findings=None, attachments=None):
    return AttachmentAnalysisResult(
        attachments=attachments or [],
        score=score,
        findings=findings or [],
        summary="",
    )


def test_low_risk_level():
    risk = build_risk_result(
        parse_email("From: a@example.com\n\nhi"),
        _sender(0), _url(0), _content(0), _attachment(0),
    )
    assert risk.level in ("LOW", "MEDIUM")  # baseline low
    assert risk.score < 35


def test_high_risk_level_when_all_high():
    risk = build_risk_result(
        parse_email("From: a@example.com\n\nhi"),
        _sender(90), _url(95), _content(80), _attachment(70),
    )
    assert risk.level == "HIGH"
    assert risk.score >= 65


def test_weights_sum_to_one():
    from analyzer.risk_engine import (
        SENDER_WEIGHT, LINKS_WEIGHT, CONTENT_WEIGHT, ATTACHMENT_WEIGHT,
    )
    total = SENDER_WEIGHT + LINKS_WEIGHT + CONTENT_WEIGHT + ATTACHMENT_WEIGHT
    assert round(total, 6) == 1.0


def test_breakdown_contains_attachment():
    risk = build_risk_result(
        parse_email("From: a@example.com\n\nhi"),
        _sender(10), _url(20), _content(15), _attachment(60),
    )
    assert "attachment" in risk.breakdown
    assert risk.breakdown["attachment"] == 60


def test_attachment_threat_card_no_longer_not_analyzed():
    risk = build_risk_result(
        parse_email("From: a@example.com\n\nhi"),
        _sender(0), _url(0), _content(0),
        _attachment(80, findings=[
            AttachmentFinding(rule="R-A1", filename="x.exe", detail="dangerous", points=35)
        ], attachments=[{"filename": "x.exe", "content_type": "application/octet-stream", "size": 1}]),
    )
    cards = {t["id"]: t for t in risk.threats}
    assert cards["attachment"]["severity"] == "HIGH"
    assert cards["attachment"]["severity"] != "NOT_ANALYZED"


def test_empty_input_safe_finding():
    risk = build_risk_result(
        parse_email("From: a@example.com\n\njust a note, nothing suspicious"),
        _sender(0), _url(0), _content(0), _attachment(0),
    )
    # With no findings at all, a SAFE finding should be present
    labels = [f["label"] for f in risk.findings]
    assert "No Threats Detected" in labels


def test_sender_analysis_flags_typosquat():
    parsed = parse_email("From: support@paypa1-site.com\n\nhi")
    res = analyze_sender(parsed)
    assert res.score >= 15
