"""
detection/domain_similarity.py

Scores how close a domain is to SEBI's official domains, with basic
homoglyph normalization (0->o, 1->l, rn->m style substitutions) since
raw edit-distance alone misses the most common phishing trick: swapping
visually-identical characters.
"""

from __future__ import annotations

import Levenshtein

OFFICIAL_DOMAINS = ["sebi.gov.in", "scores.gov.in", "smartodr.in", "investor.sebi.gov.in"]

# Common homoglyph / lookalike substitutions used in typosquatting.
_HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "5": "s", "@": "a",
    "rn": "m", "vv": "w", "cl": "d",
}


def normalize(domain: str) -> str:
    d = domain.lower()
    for fake, real in _HOMOGLYPHS.items():
        d = d.replace(fake, real)
    return d


def closest_official_match(domain: str) -> tuple[str, float]:
    """Returns (closest_official_domain, similarity_ratio 0-1), on the normalized form."""
    norm = normalize(domain)
    best_domain, best_ratio = "", 0.0
    for official in OFFICIAL_DOMAINS:
        ratio = Levenshtein.ratio(norm, normalize(official))
        if ratio > best_ratio:
            best_ratio, best_domain = ratio, official
    return best_domain, round(best_ratio, 3)


def is_exact_official(domain: str) -> bool:
    return domain.lower().strip(".") in OFFICIAL_DOMAINS


def similarity_signal(domain: str) -> dict:
    """
    Returns a structured signal for the risk engine.
    lookalike_risk is 0 unless the domain is suspiciously close WITHOUT
    being an exact match — exact matches are safe, near-misses are the danger zone.
    """
    if is_exact_official(domain):
        return {"similarity": 1.0, "closest_official": domain, "lookalike_risk": 0.0,
                "note": f"Exact match to official domain '{domain}'"}

    closest, ratio = closest_official_match(domain)
    lookalike_risk = ratio if ratio > 0.75 else 0.0
    note = (
        f"Resembles official domain '{closest}' ({ratio:.0%} similar) without matching exactly"
        if lookalike_risk else
        f"No strong resemblance to any official SEBI domain (closest: {ratio:.0%})"
    )
    return {"similarity": ratio, "closest_official": closest, "lookalike_risk": lookalike_risk, "note": note}
