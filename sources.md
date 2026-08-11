# Dataset Sources

This file exists because a judge asking "is this real data?" deserves a straight
answer per file, not a blanket claim.

## ✅ Real, sourced, verifiable

| File | What's real | Source |
|---|---|---|
| `sebi/official_domains.csv` | Domain names — publicly verifiable by visiting each site | Direct knowledge / official sites |
| `sebi/stock_brokers.csv` | Broker names and domains are real. Angel One's SEBI reg number (`INZ000161534`) is pulled verbatim from Angel One's own published disclosure. Other reg numbers deliberately left blank rather than guessed. | Angel One official site footer disclosure |
| `phishing/fake_broker_sites.csv` | 4 specific fake domains (`mcxliveresearch.in`, `paytmmoney.top`, `kotaksecurities.zerodhaweb.com`, `hdfcsec.xyz`) are real, named in a published article | Angel One, "List of Fake Websites and Apps of Listed Companies," 4 Aug 2025, citing an NSE investor-complaint circular (656 total flagged, only 4 individually named in the source) |
| `nlp/scam_keywords.csv` | Fraud *patterns* (not exact phrases) are grounded in quoted expert commentary from real reporting | Business Standard (Apr 2025 SEBI circular coverage, quoting EY Forensic & StockGro); The420.in (Jun 2026 SIDBI officer case) |
| `threat_intelligence/suspicious_tlds.csv` | `.xyz` and `.top` tie directly to the two real fake-domain examples above | Same as `fake_broker_sites.csv` |
| `threat_intelligence/homoglyphs.csv` | Standard, well-documented character-substitution techniques, matches the actual normalization logic in `domain_similarity.py` | General, publicly documented domain-spoofing technique — not incident-specific |

## ⬜ Deliberately NOT fabricated — here's why

| What the "top 1%" spec asked for | Why it's not in this repo as real data |
|---|---|
| `phishing_urls.csv` (50,000–100,000 rows) | No legitimate way to produce this at that scale without pulling from a real threat-intel feed (PhishTank, Google Safe Browsing, CERT-In). Inventing plausible-looking phishing URLs would mean publishing fabricated accusations against domain names that may not even be malicious — that's misinformation, not a dataset. |
| `fake_broker_sites.csv` at scale | Same issue — only including the 4 domains a legitimate published source actually named, not inventing more to hit a row-count target. |
| Scam messages (20,000–50,000 rows) | A real corpus at that scale would need to come from actual SCORES complaint data, which isn't public. Mass-generating synthetic scam text and presenting it as a dataset risks being mistaken for real complaint data. |
| Multilingual scam phrases (6 languages) | Same concern — would need either real complaint data per language or clearly-labeled synthetic generation, not done here to avoid the "real dataset" label being misapplied. |
| Logo hash database, QR hash database | Requires actual image assets and a hashing pipeline — infrastructure work, not a CSV that can be "found." Structure is scaffolded in the roadmap; content isn't invented. |
| `training/train.csv` etc. | A real train/val/test split needs a real labeled corpus first. Building one from the (currently placeholder) scam_keywords + fuzzy matching in `scam_language_detector.py` is a reasonable next step, not done here. |

## For production

Before relying on any of this beyond a hackathon demo:
- Replace `stock_brokers.csv` with a live, scheduled sync against SEBI's actual intermediary search
- Replace the fake-domain list with a real threat-intel feed subscription (PhishTank / Google Safe Browsing API / CERT-In advisories)
- Source scam-language training data from real SCORES complaint text (with proper authorization), not synthetic generation
