"""
main.py — PhishGuard FastAPI Backend
=====================================
Entry point for the PhishGuard analysis API.

Routes:
  GET  /          — Health check / API info
  POST /api/analyze — Analyze a raw email for phishing indicators

CORS is enabled for all origins so the frontend (served from a different
port) can call the API during local development.

Run with:
  uvicorn main:app --reload --port 8000

"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
import traceback

from analyzer.email_parser     import parse_email
from analyzer.url_analyzer     import analyze_urls
from analyzer.content_analyzer import analyze_content
from analyzer.attachment_analyzer import analyze_attachments
from analyzer.risk_engine      import analyze_sender, build_risk_result


# ── App setup ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="PhishGuard API",
    description="Rule-based phishing email analysis backend.",
    version="1.0.0",
)

# Allow requests from any origin (localhost:5500, 127.0.0.1:*, file://, etc.)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # Tighten this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response Models ─────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    """Input model — expects a single 'email' field with raw email content."""
    email: str

    @field_validator("email")
    @classmethod
    def email_must_not_be_empty(cls, v: str) -> str:
        """Reject blank or whitespace-only inputs."""
        if not v or not v.strip():
            raise ValueError("'email' field must not be empty.")
        if len(v) > 200_000:
            raise ValueError("'email' field exceeds the 200,000 character limit.")
        return v


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    """Health check and API info."""
    return {
        "service": "PhishGuard API",
        "version": "1.0.0",
        "status":  "online",
        "endpoint": "POST /api/analyze",
    }


@app.post("/api/analyze", tags=["Analysis"])
def analyze(request: AnalyzeRequest):
    """
    Analyze a raw email for phishing indicators.

    Pipeline:
      1. Parse email fields (From, Subject, Body, Attachments)
      2. Analyze sender domain
      3. Analyze embedded URLs
      4. Analyze content for social-engineering patterns
      5. Analyze attachments for malware indicators
      6. Aggregate into a risk score + structured verdict

    Returns a JSON object matching the PhishGuard frontend contract.
    """
    try:
        raw_email = request.email.strip()

        # ── Step 1: Parse email ───────────────────────────────────────────────
        parsed = parse_email(raw_email)

        # ── Step 2: Sender analysis ───────────────────────────────────────────
        sender_result = analyze_sender(parsed)

        # ── Step 3: URL analysis ──────────────────────────────────────────────
        # Scan the entire raw email (headers + body) for URLs
        url_result = analyze_urls(raw_email)

        # ── Step 4: Content analysis ──────────────────────────────────────────
        content_result = analyze_content(
            subject=parsed.subject or "",
            body=parsed.body or raw_email,
        )

        # ── Step 5: Attachment analysis ───────────────────────────────────────
        attachment_result = analyze_attachments(parsed.attachments)

        # ── Step 6: Build risk verdict ────────────────────────────────────────
        risk = build_risk_result(parsed, sender_result, url_result, content_result, attachment_result)

        # ── Return response matching frontend contract ─────────────────────────
        return {
            "score":          risk.score,
            "level":          risk.level,
            "breakdown":      risk.breakdown,
            "threats":        risk.threats,
            "findings":       risk.findings,
            "recommendation": risk.recommendation,
        }

    except ValueError as e:
        # Pydantic validation errors surface here too
        raise HTTPException(status_code=422, detail=str(e))

    except Exception:
        # Log the full traceback server-side but return a safe error to client
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail="Internal analysis error. Please try again or contact support."
        )
