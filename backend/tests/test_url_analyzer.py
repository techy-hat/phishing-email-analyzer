"""Tests for the URL analyzer module."""

import pytest

from analyzer.url_analyzer import analyze_urls


def test_no_urls():
    result = analyze_urls("No links here at all.")
    assert result.urls == []
    assert result.score == 0
    assert result.findings == []


def test_ip_host_high_score():
    result = analyze_urls("Visit http://192.168.1.105/login now")
    assert result.score >= 35
    rule_ids = {f.rule_id for f in result.findings}
    assert "R1" in rule_ids


def test_at_symbol_url():
    result = analyze_urls("Go to http://paypal.com@evil.com/login")
    # @ in URL flagged
    assert any(f.rule_id == "R2" for f in result.findings)


def test_suspicious_domain_keyword():
    result = analyze_urls("http://secure-login-verify.com/account")
    assert any(f.rule_id == "R4" for f in result.findings)


def test_http_not_https():
    result = analyze_urls("http://example.com")
    assert any(f.rule_id == "R5" for f in result.findings)


def test_url_shortener():
    result = analyze_urls("http://bit.ly/abc123")
    assert any(f.rule_id == "R6" for f in result.findings)


def test_dedup_urls():
    result = analyze_urls("http://example.com http://example.com http://example.com")
    assert result.urls == ["http://example.com"]


def test_bare_www_normalized():
    result = analyze_urls("go to www.example.com now")
    assert result.urls == ["http://www.example.com"]


def test_single_malicious_url_drives_score():
    # A clean URL plus one malicious URL -> score driven high by the bad one
    result = analyze_urls("http://trusted.com/path http://192.168.0.5/verify")
    assert result.score >= 35
