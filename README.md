---

# ⚖️ What's Real vs Planned

| Capability | Status |
|---|---|
| Domain similarity, SSL & WHOIS checks | ✅ Working |
| SSRF protection | ✅ Working |
| Rate limiting | ✅ Working |
| Screenshot OCR | ✅ Working |
| Scam-language detection | ✅ Working |
| Brand impersonation detection | ✅ Working |
| Explainable risk engine | ✅ Working |
| Frontend verification console | ✅ Working |
| QR verification | ⏳ Planned |
| Registered intermediary verification | ⏳ Planned |
| Digital authentication layer | ⏳ Designed |
| Deepfake video detection | ⏳ Phase 2 |
| PostgreSQL integration | ⏳ Planned |

The project intentionally separates **implemented functionality** from future capabilities.

---

# 🔐 Security

SEBI Trust Shield follows a security-first approach.

### SSRF Protection

Every user-supplied URL passes through a security layer before network requests.

Protection includes:

- Private IP blocking
- Loopback address blocking
- Link-local address blocking
- Cloud metadata endpoint blocking
- URL scheme validation
- Port validation
- DNS resolution checks

### Rate Limiting

The API uses a sliding-window rate limiter:

```text
20 requests / 60 seconds
per IP / endpoint