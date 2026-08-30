"""Tests for the content analyzer module."""

import pytest

from analyzer.content_analyzer import analyze_content


def test_empty_content_zero_score():
    result = analyze_content(subject="", body="")
    assert result.score == 0
    assert result.findings == []


def test_urgency_category():
    result = analyze_content(subject="", body="ACT NOW or your account will be suspended.")
    cats = set(f.category for f in result.findings)
    assert "C1" in cats
    assert result.score > 0


def test_credential_request_category():
    result = analyze_content(subject="", body="Please verify your password to continue.")
    cats = set(f.category for f in result.findings)
    assert "C2" in cats


def test_threat_fear_category():
    result = analyze_content(subject="", body="Legal action will be taken against you.")
    cats = set(f.category for f in result.findings)
    assert "C3" in cats


def test_financial_bait_category():
    result = analyze_content(subject="", body="Congratulations, you have won a prize!")
    cats = set(f.category for f in result.findings)
    assert "C4" in cats


def test_subject_weighted_double():
    # Same phrase in subject should be detected (subject is scanned twice)
    result = analyze_content(subject="URGENT", body="")
    assert result.score > 0


def test_score_capped_at_100():
    body = (
        "ACT NOW, verify your password, legal action, you have won a prize, "
        "claim your reward, unauthorized access, your account is suspended, "
        "within 24 hours, final notice, confirm your credentials immediately."
    )
    result = analyze_content(subject="URGENT ACTION REQUIRED", body=body)
    assert result.score <= 100
