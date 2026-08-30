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

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
import traceback

from analyzer.email_parser     import parse_email
from analyzer.url_analyzer     import analyze_urls
from analyzer.content_analyzer import analyze_content
from analyzer.attachment_analyzer import analyze_attachments
from analyzer.header_analyzer  import analyze_headers
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
        "version": "1.1.0",
        "status":  "online",
        "endpoint": "POST /api/analyze",
        "endpoint_eml": "POST /api/analyze-eml",
    }


def _run_pipeline(request, raw_email: str):
    """
    Shared analysis pipeline used by both /api/analyze and /api/analyze-eml.
    Raises HTTPException on failure.
    """
    parsed = parse_email(raw_email)

    sender_result = analyze_sender(parsed)
    url_result = analyze_urls(raw_email)
    content_result = analyze_content(
        subject=parsed.subject or "",
        body=parsed.body or raw_email,
    )
    attachment_result = analyze_attachments(parsed.attachments)
    header_result = analyze_headers(parsed)

    risk = build_risk_result(
        parsed,
        sender_result,
        url_result,
        content_result,
        attachment_result,
        header_result,
    )

    return {
        "score":          risk.score,
        "level":          risk.level,
        "classification": risk.classification,
        "confidence":     risk.confidence,
        "breakdown":      risk.breakdown,
        "threats":        risk.threats,
        "findings":       risk.findings,
        "authentication": risk.authentication,
        "evidence":       risk.evidence,
        "recommendation": risk.recommendation,
    }


@app.post("/api/analyze", tags=["Analysis"])
def analyze(request: AnalyzeRequest):
    """
    Analyze a raw email for phishing indicators.

    Pipeline:
      1. Parse email fields (From, Subject, Body, Attachments, Headers)
      2. Analyze sender domain
      3. Analyze embedded URLs
      4. Analyze content for social-engineering patterns
      5. Analyze attachments for malware indicators
      6. Analyze headers & SPF/DKIM/DMARC authentication
      7. Aggregate into a risk score + structured verdict

    Returns a JSON object matching the PhishGuard frontend contract.
    """
    try:
        raw_email = request.email.strip()
        return _run_pipeline(request, raw_email)
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


class EmlUploadResponse(BaseModel):
    """Confirmation envelope returned after a successful .eml upload + analysis."""
    detail: str
    result: dict


@app.post("/api/analyze-eml", tags=["Analysis"])
async def analyze_eml(
    file: UploadFile = File(...),
):
    """
    Analyze a .eml (or .txt) file upload.

    Reads the uploaded file (max 10 MB), decodes it as raw email bytes, and
    runs the full analysis pipeline — preserving the complete header block so
    SPF/DKIM/DMARC and Reply-To/Return-Path checks can run on real data.
    """
    MAX_EML_BYTES = 10 * 1024 * 1024
    data = await file.read(MAX_EML_BYTES + 1)
    if len(data) > MAX_EML_BYTES:
        raise HTTPException(status_code=413, detail="Uploaded file exceeds the 10 MB limit.")

    name = (file.filename or "").lower()
    if not name.endswith((".eml", ".txt")):
        raise HTTPException(status_code=415, detail="Only .eml and .txt files are supported.")

    try:
        raw = data.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=422, detail="Could not decode the uploaded file as text.")

    if not raw.strip():
        raise HTTPException(status_code=422, detail="The uploaded file is empty.")

    try:
        result = _run_pipeline(file, raw)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Internal analysis error. Please try again.")

    return EmlUploadResponse(
        detail=f"Analyzed uploaded file '{file.filename or 'upload.eml'}'.",
        result=result,
    )
