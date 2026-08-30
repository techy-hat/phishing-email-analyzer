"""Integration tests for the /api/analyze endpoint via FastAPI TestClient."""

import pytest
from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


PHISHING_EMAIL = (
    "From: PayPal Support <security@paypa1-secure-login.com>\n"
    "To: victim@example.com\n"
    "Subject: URGENT: Your PayPal account has been suspended - Verify immediately\n\n"
    "Dear Valued Customer,\n\n"
    "We have detected unauthorized access to your PayPal account. Your account will be\n"
    "permanently terminated within 24 hours unless you verify your credentials immediately.\n\n"
    "CLICK HERE TO VERIFY YOUR ACCOUNT:\n"
    "http://paypa1-secure-login.com/account/verify/login?user=victim@example.com\n\n"
    "You must act now. Failure to verify within 24 hours will result in permanent account\n"
    "suspension and possible legal action.\n\n"
    "PayPal Security Team\n"
)

BENIGN_EMAIL = (
    "From: Acme Corp <newsletter@acme.example>\n"
    "To: user@example.com\n"
    "Subject: Monthly newsletter\n\n"
    "Hi there,\n\n"
    "Thank you for subscribing. Here is your monthly newsletter with the latest updates.\n\n"
    "Best regards,\nThe Acme Team\n"
)


def test_root_health_check():
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "online"


def test_analyze_returns_expected_contract():
    resp = client.post("/api/analyze", json={"email": PHISHING_EMAIL})
    assert resp.status_code == 200
    data = resp.json()

    assert set(["score", "level", "breakdown", "threats", "findings", "recommendation"]).issubset(data.keys())
    assert 0 <= data["score"] <= 100
    assert data["level"] in ("HIGH", "MEDIUM", "LOW")
    assert "attachment" in data["breakdown"]  # new attachment sub-score present
    assert isinstance(data["threats"], list)
    assert isinstance(data["findings"], list)


def test_analyze_flags_phishing_as_high_risk():
    resp = client.post("/api/analyze", json={"email": PHISHING_EMAIL})
    data = resp.json()
    # Typosquatted sender + malicious URL should drive this to HIGH
    assert data["score"] >= 50


def test_analyze_benign_low_risk():
    resp = client.post("/api/analyze", json={"email": BENIGN_EMAIL})
    data = resp.json()
    assert data["score"] < 35
    assert data["level"] == "LOW"


def test_analyze_rejects_empty_email():
    resp = client.post("/api/analyze", json={"email": "   "})
    assert resp.status_code == 422


def test_analyze_rejects_missing_email_field():
    resp = client.post("/api/analyze", json={})
    assert resp.status_code == 422


def test_analyze_attachment_indicators():
    with_attachment = (
        "From: a@example.com\n"
        "To: b@example.com\n"
        "Subject: Invoice\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=\"BOUNDARY1\"\n"
        "\n"
        "--BOUNDARY1\n"
        "Content-Type: text/plain\n"
        "\n"
        "Please see attached invoice.\n"
        "--BOUNDARY1\n"
        "Content-Type: application/octet-stream; name=\"invoice.exe\"\n"
        "Content-Disposition: attachment; filename=\"invoice.exe\"\n"
        "\n"
        "fake-binary\n"
        "--BOUNDARY1--\n"
    )
    resp = client.post("/api/analyze", json={"email": with_attachment})
    assert resp.status_code == 200
    data = resp.json()
    assert data["breakdown"]["attachment"] >= 35
