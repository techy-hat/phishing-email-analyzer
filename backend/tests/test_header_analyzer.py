"""Tests for the header & authentication analyzer and confidence/evidence output."""

from analyzer.email_parser import parse_email
from analyzer.header_analyzer import analyze_headers
from analyzer.risk_engine import (
    SenderAnalysisResult, SenderFinding,
    UrlAnalysisResult,
    build_risk_result,
)


def _sender(score, findings=None):
    return SenderAnalysisResult(score=score, findings=findings or [], summary="")


def _url(score, findings=None, urls=None):
    return UrlAnalysisResult(urls=urls or [], score=score, findings=findings or [], summary="")


def _content_score(score):
    from analyzer.content_analyzer import ContentAnalysisResult
    return ContentAnalysisResult(score=score, findings=[], categories_hit=[], summary="")


def _attachment_score(score):
    from analyzer.attachment_analyzer import AttachmentAnalysisResult
    return AttachmentAnalysisResult(attachments=[], score=score, findings=[], summary="")


AUTH_PASS = (
    "From: Acme Corp <news@acme.example>\n"
    "To: user@example.com\n"
    "Subject: Newsletter\n"
    "Authentication-Results: mx.google.com;\n"
    "    spf=pass (google.com: domain of news@acme.example designates host as permitted sender)\n"
    "    smtp.mailfrom=news@acme.example;\n"
    "    dkim=pass header.i=@acme.example;\n"
    "    dmarc=pass (p=NONE sp=NONE dis=NONE)\n"
    "\n"
    "Hello!\n"
)


def test_auth_pass_parsed_correctly():
    parsed = parse_email(AUTH_PASS)
    assert parsed.spf == "pass"
    assert parsed.dkim == "pass"
    assert parsed.dmarc == "pass"
    res = analyze_headers(parsed)
    assert res.auth.present is True
    assert res.auth.spf == "pass"
    assert res.auth.dmarc == "pass"
    # Passing auth should not add auth failure findings
    assert not any("Auth" in f.label and "Failed" in f.label for f in res.findings)


def test_reply_to_mismatch_flagged():
    parsed = parse_email(
        "From: support@acme.example\n"
        "Reply-To: attacker@evil.example\n"
        "To: user@example.com\n"
        "Subject: Hi\n\nbody\n"
    )
    res = analyze_headers(parsed)
    assert res.score >= 25
    assert any("Reply-To" in f.label for f in res.findings)


def test_auth_failures_score_header():
    parsed = parse_email(
        "From: spoofed@victim-bank.com\n"
        "To: user@example.com\n"
        "Subject: Verify\n"
        "Authentication-Results: mx.example.com;\n"
        "    spf=fail smtp.mailfrom=spoofed@victim-bank.com;\n"
        "    dkim=fail header.i=@victim-bank.com;\n"
        "    dmarc=fail (p=REJECT sp=REJECT dis=QUARANTINE)\n"
        "\n"
        "Click the link.\n"
    )
    res = analyze_headers(parsed)
    assert res.auth.spf == "fail"
    assert res.auth.dmarc == "fail"
    assert res.score >= 30


def test_confidence_drops_when_no_headers():
    parsed = parse_email("From: a@example.com\n\njust a note")
    risk = build_risk_result(
        parsed,
        _sender(0),
        _url(0),
        _content_score(0),
        _attachment_score(0),
        analyze_headers(parsed),
    )
    # No structured headers → confidence should be reduced from 1.0
    assert risk.confidence < 1.0
    assert 0.0 <= risk.confidence <= 1.0


def test_confidence_high_with_full_headers_and_auth():
    parsed = parse_email(AUTH_PASS)
    risk = build_risk_result(
        parsed,
        _sender(0),
        _url(0),
        _content_score(0),
        _attachment_score(0),
        analyze_headers(parsed),
    )
    assert risk.confidence >= 0.9


def test_evidence_present_and_classification():
    parsed = parse_email(AUTH_PASS)
    header_res = analyze_headers(parsed)
    risk = build_risk_result(
        parsed,
        _sender(0),
        _url(0),
        _content_score(0),
        _attachment_score(0),
        header_res,
    )
    assert isinstance(risk.evidence, list)
    assert len(risk.evidence) > 0
    assert risk.classification in ("likely_phishing", "suspicious", "likely_benign")
    # authentication summary dict is returned
    assert "spf" in risk.authentication and "dmarc" in risk.authentication


def test_evidence_lists_flags_for_flagged_email():
    parsed = parse_email(
        "From: PayPal Support <security@paypa1-login.com>\n"
        "Reply-To: attacker@evil.example\n"
        "To: user@example.com\n"
        "Subject: URGENT verify\n"
        "Authentication-Results: mx.example.com; dmarc=fail; spf=fail\n"
        "\n"
        "Verify now at http://secure-login-paypal-verify.com\n"
    )
    risk = build_risk_result(
        parsed,
        _sender(80, findings=[SenderFinding("Sender Domain Mismatch", "mismatch", 45)]),
        _url(60, findings=[], urls=["http://secure-login-paypal-verify.com"]),
        _content_score(40),
        _attachment_score(0),
        analyze_headers(parsed),
    )
    # Evidence should contain flag-related bullets
    joined = " ".join(risk.evidence)
    assert risk.evidence, "expected non-empty evidence"
