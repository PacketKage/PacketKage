"""Tests for the auth rate limiter."""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.auth.rate_limit import (
    RateLimiter,
    _client_ip,
)


def _make_request(ip: str = "1.2.3.4", x_forwarded_for: str | None = None) -> Request:
    headers = []
    if x_forwarded_for:
        headers.append((b"x-forwarded-for", x_forwarded_for.encode("utf-8")))

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/auth/login",
        "headers": headers,
        "client": (ip, 12345),
    }
    return Request(scope)


def test_rate_limiter_allows_under_limit():
    limiter = RateLimiter(window=60, limit=5)
    for _ in range(5):
        limiter.check("10.0.0.1")  # should not raise


def test_rate_limiter_blocks_over_limit():
    limiter = RateLimiter(window=60, limit=3)
    for _ in range(3):
        limiter.check("10.0.0.1")

    with pytest.raises(HTTPException) as exc_info:
        limiter.check("10.0.0.1")

    assert exc_info.value.status_code == 429
    assert "Retry-After" in exc_info.value.headers
    assert int(exc_info.value.headers["Retry-After"]) >= 1


def test_rate_limiter_distinct_ips():
    limiter = RateLimiter(window=60, limit=2)
    limiter.check("10.0.0.1")
    limiter.check("10.0.0.1")

    # Second IP is independent
    limiter.check("10.0.0.2")
    limiter.check("10.0.0.2")

    with pytest.raises(HTTPException):
        limiter.check("10.0.0.1")


def test_client_ip_extraction():
    # Direct client IP
    req = _make_request(ip="192.168.1.50")
    assert _client_ip(req) == "192.168.1.50"

    # X-Forwarded-For takes precedence (first IP in chain)
    req_fwd = _make_request(ip="10.0.0.1", x_forwarded_for="203.0.113.195, 70.41.3.18, 150.172.238.178")
    assert _client_ip(req_fwd) == "203.0.113.195"
