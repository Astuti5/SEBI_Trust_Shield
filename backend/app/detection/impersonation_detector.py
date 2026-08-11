"""
detection/impersonation_detector.py

Cheap but effective signal: if extracted text (from a screenshot, or a
page's own body) claims to be from SEBI / RBI / a named registered
intermediary, but the domain being checked doesn't match that entity's
official domain, that mismatch IS the phishing pattern. This is how most
fake-circular and fake-broker scams actually present themselves —
official-sounding text on an unofficial domain.
"""

from __future__ import annotations

import re

from app.detection.domain_similarity import OFFICIAL_DOMAINS

# Regulator / high-value brand names commonly impersonated in the wild.
WATCHED_BRANDS = {
    "sebi": ["sebi.gov.in", "scores.gov.in", "smartodr.in", "investor.sebi.gov.in"],
    "rbi": ["rbi.org.in"],
    "nse": ["nseindia.com"],
    "bse": ["bseindia.com"],
}


def _mentions_brand(text: str, brand: str) -> bool:
    return re.search(rf"\b{re.escape(brand)}\b", text, re.IGNORECASE) is not None


def check_impersonation(extracted_text: str, checked_domain: str) -> dict:
    """
    Returns {risk: 0-1, flagged_brand: str|None, note: str}
    """
    if not extracted_text or not extracted_text.strip():
        return {"risk": 0.0, "flagged_brand": None, "note": "No text available to check for brand claims"}

    domain = checked_domain.lower().strip(".")

    for brand, official_domains in WATCHED_BRANDS.items():
        if _mentions_brand(extracted_text, brand):
            if domain in official_domains:
                continue  # genuinely on the brand's own domain — not impersonation
            return {
                "risk": 0.85,
                "flagged_brand": brand.upper(),
                "note": (
                    f"Content claims association with {brand.upper()} but is hosted on "
                    f"'{domain}', which does not match {brand.upper()}'s official domain(s) "
                    f"({', '.join(official_domains)})"
                ),
            }

    return {"risk": 0.0, "flagged_brand": None, "note": "No brand-impersonation pattern detected"}
