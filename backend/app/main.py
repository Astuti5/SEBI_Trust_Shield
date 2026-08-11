"""
app/main.py — SEBI Trust Shield backend.

Two working endpoints:
  GET  /check-url        — domain similarity + SSL + WHOIS age, SSRF-guarded, rate-limited
  POST /check-screenshot  — OCR + scam-language + impersonation + (optional) URL signals
  GET  /health

Run:
    pip install -r requirements.txt
    apt-get install -y tesseract-ocr   # only needed for /check-screenshot
    uvicorn app.main:app --reload
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.core.rate_limit import rate_limit
from app.core.security import SSRFError, assert_safe_url
from app.detection import (
    domain_similarity,
    impersonation_detector,
    ocr_service,
    risk_engine,
    scam_language_detector,
    whois_ssl_service,
)

app = FastAPI(
    title="SEBI Trust Shield API",
    version="0.2.0",
    description="Detect the fake. Authenticate the real.",
)

# Wide open for hackathon demo purposes — restrict to the actual frontend
# origin before any real deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class RiskResponse(BaseModel):
    input_type: str
    domain: str | None = None
    risk_score: float
    risk_level: str
    signals: dict
    reasons: list[str]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/check-url", response_model=RiskResponse, dependencies=[Depends(rate_limit)])
def check_url(url: str):
    """Live domain-similarity + SSL + WHOIS check. SSRF-guarded."""
    if not url or len(url) < 4:
        raise HTTPException(status_code=400, detail="Provide a valid URL")

    try:
        network = whois_ssl_service.run_network_checks(url)
    except SSRFError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    domain = network["domain"]
    sim = domain_similarity.similarity_signal(domain)

    report = risk_engine.score(
        exact_official_match=domain_similarity.is_exact_official(domain),
        lookalike_domain_risk=sim["lookalike_risk"],
        lookalike_note=sim["note"],
        ssl_risk=network["ssl"]["risk"],
        ssl_note=network["ssl"]["note"],
        whois_age_risk=network["whois"]["risk"],
        whois_note=network["whois"]["note"],
    )

    return RiskResponse(
        input_type="url",
        domain=domain,
        risk_score=report.risk_score,
        risk_level=report.risk_level,
        signals=report.signals,
        reasons=report.reasons,
    )


@app.post("/check-screenshot", response_model=RiskResponse, dependencies=[Depends(rate_limit)])
async def check_screenshot(
    file: UploadFile = File(...),
    claimed_url: str | None = Form(default=None, description="Optional: URL the screenshot claims to be from"),
):
    """OCR + scam-language + brand-impersonation check on an uploaded screenshot."""
    if file.content_type not in {"image/png", "image/jpeg", "image/webp"}:
        raise HTTPException(status_code=400, detail="Upload a PNG, JPEG, or WEBP image")

    image_bytes = await file.read()
    if len(image_bytes) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Image too large (max 10MB)")

    try:
        text = ocr_service.extract_text(image_bytes)
    except ocr_service.OCRUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e

    domain_for_check = ""
    sim_signal = None
    if claimed_url:
        try:
            hostname, _ = assert_safe_url(claimed_url)
            domain_for_check = hostname
            sim_signal = domain_similarity.similarity_signal(hostname)
        except SSRFError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    scam_signal = scam_language_detector.match_scam_language(text)
    impersonation_signal = impersonation_detector.check_impersonation(text, domain_for_check)

    report = risk_engine.score(
        lookalike_domain_risk=sim_signal["lookalike_risk"] if sim_signal else None,
        lookalike_note=sim_signal["note"] if sim_signal else "",
        scam_language_risk=scam_signal["risk"],
        scam_language_note=scam_signal["note"],
        impersonation_risk=impersonation_signal["risk"],
        impersonation_note=impersonation_signal["note"],
    )

    return RiskResponse(
        input_type="screenshot",
        domain=domain_for_check or None,
        risk_score=report.risk_score,
        risk_level=report.risk_level,
        signals=report.signals,
        reasons=report.reasons or ["Extracted text did not match any known risk pattern"],
    )
