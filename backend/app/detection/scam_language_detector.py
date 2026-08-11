"""
detection/scam_language_detector.py

Phase 1 implementation: fuzzy similarity search (stdlib difflib) against a
seed set of known scam phrases, in short sliding windows of the input text.
This is deliberately NOT a trained classifier — matches the honest scope
stated in the deck: "embedding-similarity search against seed phrases,
upgradeable to a fine-tuned classifier once complaint volume justifies it."

difflib.SequenceMatcher is used instead of a real embedding model so this
runs with zero extra ML dependencies and zero GPU/API cost — a reasonable
Phase 1 trade for a hackathon MVP. Swap in a proper sentence-embedding
model (e.g. sentence-transformers) behind the same match_scam_language()
signature when ready; nothing downstream needs to change.
"""

from __future__ import annotations

import json
from difflib import SequenceMatcher
from pathlib import Path

_SEED_PATH = Path(__file__).resolve().parents[3] / "datasets" / "scam_phrases_seed.json"
_MATCH_THRESHOLD = 0.55


def _load_seed_phrases() -> list[str]:
    try:
        data = json.loads(_SEED_PATH.read_text())
        return data.get("phrases", [])
    except FileNotFoundError:
        return []


_SEED_PHRASES = _load_seed_phrases()


def _windows(text: str, size: int = 8) -> list[str]:
    """Slide an N-word window over the text so a long paragraph doesn't
    dilute one strong scam phrase into a low overall similarity score."""
    words = text.split()
    if len(words) <= size:
        return [text]
    return [" ".join(words[i:i + size]) for i in range(0, len(words) - size + 1, 4)]


def match_scam_language(text: str) -> dict:
    """
    Returns {risk: 0-1, matches: [{phrase, window, score}], note: str}
    """
    if not text or not text.strip():
        return {"risk": 0.0, "matches": [], "note": "No text to analyze"}
    if not _SEED_PHRASES:
        return {"risk": 0.0, "matches": [], "note": "Seed phrase set failed to load"}

    text_lower = text.lower()
    matches = []
    for window in _windows(text_lower):
        for phrase in _SEED_PHRASES:
            score = SequenceMatcher(None, window, phrase).ratio()
            if score >= _MATCH_THRESHOLD:
                matches.append({"phrase": phrase, "matched_text": window, "score": round(score, 2)})

    matches.sort(key=lambda m: m["score"], reverse=True)
    top = matches[:5]

    if not top:
        return {"risk": 0.0, "matches": [], "note": "No known scam-language patterns matched"}

    risk = min(1.0, max(m["score"] for m in top))
    note = f"{len(top)} scam-language pattern(s) matched, strongest: \"{top[0]['phrase']}\" ({top[0]['score']:.0%})"
    return {"risk": round(risk, 2), "matches": top, "note": note}
