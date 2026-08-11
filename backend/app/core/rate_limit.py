"""
core/rate_limit.py — real rate limiting, not a claim in a slide.

In-memory sliding-window limiter keyed by client IP. Good enough for a
single-process hackathon deployment; swap the store for Redis
(INCR + EXPIRE) before running multiple workers or instances — that
swap point is marked below so it's not forgotten.

Usage (in a route):
    from fastapi import Depends
    from app.core.rate_limit import rate_limit

    @app.get("/check-url", dependencies=[Depends(rate_limit)])
    def check_url(...): ...
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

WINDOW_SECONDS = 60
MAX_REQUESTS_PER_WINDOW = 20  # per IP, per endpoint

# NOTE: process-local memory. Move to Redis (INCR key, EXPIRE WINDOW_SECONDS)
# before deploying more than one backend worker/instance, or each worker
# will enforce its own independent limit and the real ceiling becomes
# MAX_REQUESTS_PER_WINDOW * worker_count.
_hits: dict[str, deque[float]] = defaultdict(deque)


def _client_key(request: Request) -> str:
    # Respect a trusted proxy header if present (set by your reverse proxy),
    # otherwise fall back to the raw connecting IP.
    forwarded = request.headers.get("x-forwarded-for")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")
    return f"{ip}:{request.url.path}"


def rate_limit(request: Request) -> None:
    key = _client_key(request)
    now = time.monotonic()
    window = _hits[key]

    while window and now - window[0] > WINDOW_SECONDS:
        window.popleft()

    if len(window) >= MAX_REQUESTS_PER_WINDOW:
        retry_after = int(WINDOW_SECONDS - (now - window[0]))
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded — max {MAX_REQUESTS_PER_WINDOW} requests per "
                    f"{WINDOW_SECONDS}s. Retry in ~{max(retry_after, 1)}s.",
            headers={"Retry-After": str(max(retry_after, 1))},
        )

    window.append(now)
