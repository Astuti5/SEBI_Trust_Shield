"""
detection/risk_engine.py

Combines every available signal into one explainable Low/Medium/High score.
Weights are intentionally simple, named constants — not a trained model —
per the design decision logged in docs/architecture.md: explainability
over marginal accuracy, because a false "this is fake" costs more trust
than a false "this looks fine" in a regulator-facing tool.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Weights sum to 1.0 across whichever signals are actually available for a
# given check (URL-only vs URL+screenshot). See _normalize_weights below —
# missing signals don't silently count as "safe", their weight is
# redistributed across the signals that DID run.
BASE_WEIGHTS = {
    "lookalike_domain": 0.30,
    "ssl": 0.20,
    "whois_age": 0.15,
    "scam_language": 0.20,
    "impersonation": 0.15,
}

LOW_MAX = 0.33
MEDIUM_MAX = 0.66


@dataclass
class RiskReport:
    risk_score: float
    risk_level: str
    signals: dict = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)


def _normalize_weights(present_signal_keys: list[str]) -> dict[str, float]:
    total = sum(BASE_WEIGHTS[k] for k in present_signal_keys)
    if total == 0:
        return {}
    return {k: BASE_WEIGHTS[k] / total for k in present_signal_keys}


def score(
    *,
    lookalike_domain_risk: float | None = None,
    lookalike_note: str = "",
    ssl_risk: float | None = None,
    ssl_note: str = "",
    whois_age_risk: float | None = None,
    whois_note: str = "",
    scam_language_risk: float | None = None,
    scam_language_note: str = "",
    impersonation_risk: float | None = None,
    impersonation_note: str = "",
    exact_official_match: bool = False,
) -> RiskReport:
    """
    Any signal left as None is treated as "not run" and excluded from the
    weighted average (its weight is redistributed), not silently scored as 0.
    """
    if exact_official_match:
        return RiskReport(
            risk_score=0.0,
            risk_level="Low",
            signals={"exact_official_match": True},
            reasons=["Domain is an exact match to an official SEBI domain"],
        )

    raw = {
        "lookalike_domain": (lookalike_domain_risk, lookalike_note),
        "ssl": (ssl_risk, ssl_note),
        "whois_age": (whois_age_risk, whois_note),
        "scam_language": (scam_language_risk, scam_language_note),
        "impersonation": (impersonation_risk, impersonation_note),
    }
    present = {k: v for k, v in raw.items() if v[0] is not None}
    if not present:
        return RiskReport(risk_score=0.0, risk_level="Low", signals={},
                           reasons=["No signals were available to score"])

    weights = _normalize_weights(list(present.keys()))
    weighted_sum = sum(weights[k] * present[k][0] for k in present)
    risk_score = round(min(1.0, max(0.0, weighted_sum)), 2)

    if risk_score >= MEDIUM_MAX:
        level = "High"
    elif risk_score >= LOW_MAX:
        level = "Medium"
    else:
        level = "Low"

    reasons = [note for _, note in present.values() if note]
    signals = {k: round(v[0], 2) for k, v in present.items()}

    return RiskReport(risk_score=risk_score, risk_level=level, signals=signals, reasons=reasons)
