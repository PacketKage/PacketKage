"""In-process IP-based rate limiting for sensitive endpoints.

This module provides a simple, dependency-free sliding-window rate limiter
backed by an in-memory dict.  It is designed for **single-process** deployments
(the default ``uvicorn`` invocation).  Multi-worker setups behind a reverse
proxy should apply rate limiting at the proxy layer (e.g. nginx ``limit_req``)
instead of — or in addition to — this module.

Usage in FastAPI:

    from app.auth.rate_limit import rate_limit_login

    @router.get("/login")
    async def login(
        request: Request,
        _rl: None = Depends(rate_limit_login),
    ) -> ...:
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from threading import Lock
from typing import NamedTuple

from fastapi import HTTPException, Request

logger = logging.getLogger("packetkage.ratelimit")

# ---- Configuration ---------------------------------------------------------
# Intentionally conservative: auth endpoints are low-throughput by nature.
# ``/login`` triggers an OIDC redirect (no secret exchanged), so a slightly
# higher budget is acceptable.  ``/callback`` carries a one-time auth code and
# is more sensitive.

LOGIN_WINDOW_SECS = 60
LOGIN_MAX_REQUESTS = 15

CALLBACK_WINDOW_SECS = 60
CALLBACK_MAX_REQUESTS = 10

# Periodic cleanup: evict stale buckets after this many check() calls.
_CLEANUP_EVERY = 200


class _Bucket(NamedTuple):
    timestamps: list[float]


class RateLimiter:
    """Sliding-window counter keyed by client IP."""

    def __init__(self, window: int, limit: int) -> None:
        self._window = window
        self._limit = limit
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()
        self._calls_since_cleanup = 0

    # ------------------------------------------------------------------
    def check(self, key: str) -> None:
        """Raise ``HTTPException(429)`` if *key* has exceeded the rate limit."""
        now = time.monotonic()
        with self._lock:
            self._calls_since_cleanup += 1
            if self._calls_since_cleanup >= _CLEANUP_EVERY:
                self._evict_stale(now)
                self._calls_since_cleanup = 0

            bucket = self._buckets[key]
            cutoff = now - self._window
            # Trim timestamps older than the window.
            while bucket and bucket[0] <= cutoff:
                bucket.pop(0)

            if len(bucket) >= self._limit:
                retry_after = int(bucket[0] + self._window - now) + 1
                logger.warning(
                    "Rate limit exceeded for %s (limit=%d/%ds)",
                    key,
                    self._limit,
                    self._window,
                )
                raise HTTPException(
                    status_code=429,
                    detail="Too many requests — please try again later.",
                    headers={"Retry-After": str(retry_after)},
                )
            bucket.append(now)

    # ------------------------------------------------------------------
    def _evict_stale(self, now: float) -> None:
        cutoff = now - self._window
        stale = [k for k, ts in self._buckets.items() if not ts or ts[-1] <= cutoff]
        for k in stale:
            del self._buckets[k]


# ---- Singletons for the two auth routes ------------------------------------
_login_limiter = RateLimiter(window=LOGIN_WINDOW_SECS, limit=LOGIN_MAX_REQUESTS)
_callback_limiter = RateLimiter(window=CALLBACK_WINDOW_SECS, limit=CALLBACK_MAX_REQUESTS)


def _client_ip(request: Request) -> str:
    """Best-effort client IP extraction.

    Respects ``X-Forwarded-For`` when the app is behind a trusted reverse
    proxy (all documented deployment guides place PacketKage behind one).
    Falls back to the direct peer address.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # First entry is the original client.
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


# ---- FastAPI Depends callables ---------------------------------------------

def rate_limit_login(request: Request) -> None:
    """Dependency that rate-limits ``/api/auth/login``."""
    _login_limiter.check(_client_ip(request))


def rate_limit_callback(request: Request) -> None:
    """Dependency that rate-limits ``/api/auth/callback``."""
    _callback_limiter.check(_client_ip(request))
