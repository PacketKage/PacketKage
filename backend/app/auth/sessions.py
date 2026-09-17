"""Server-side application sessions minted after a successful OIDC login.

The browser only ever holds an opaque random token inside an HttpOnly cookie.
Identity, role mapping and expiry live in ``auth_sessions``; deleting the row
(or letting it lapse) revokes access without waiting for IdP-side timeouts.
"""

from __future__ import annotations

import base64
import json
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import Response
from sqlalchemy.orm import Session

from app.db.orm import AuthSessionModel, utcnow

OIDC_STATE_COOKIE = "packetkage_oidc"


def encode_oidc_payload(payload: dict) -> str:
    """Serialize OIDC handshake state into a cookie-safe value.

    Base64url avoids the RFC 6265 quoting/octal-escape issues that raw JSON
    triggers in ``Set-Cookie`` (SimpleCookie-style ``\\054`` escapes).
    """
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_oidc_payload(value: str) -> dict | None:
    try:
        raw = base64.urlsafe_b64decode(value.encode("ascii"))
        decoded = json.loads(raw)
    except (ValueError, TypeError, base64.binascii.Error):
        return None
    return decoded if isinstance(decoded, dict) else None


def utc_now_ts() -> float:
    return datetime.now(UTC).timestamp()


def create_session(
    db: Session,
    *,
    sub: str,
    username: str,
    email: str | None,
    groups: list[str],
    roles: list[str],
    ttl_seconds: int,
) -> AuthSessionModel:
    token = secrets.token_urlsafe(48)
    now = utcnow()
    session = AuthSessionModel(
        id=token,
        sub=sub,
        username=username,
        email=email,
        groups=groups,
        roles=roles,
        created_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
    )
    db.add(session)
    db.commit()
    return session


def lookup_session(db: Session, token: str) -> AuthSessionModel | None:
    if not token:
        return None
    return db.get(AuthSessionModel, token)


def session_is_valid(session: AuthSessionModel, now: datetime | None = None) -> bool:
    expiry = session.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=UTC)
    return (now or utcnow()).replace(tzinfo=UTC) < expiry


def revoke_session(db: Session, token: str) -> None:
    session = lookup_session(db, token)
    if session is not None:
        db.delete(session)
        db.commit()


def set_session_cookie(response: Response, session: AuthSessionModel, *, secure: bool) -> None:
    response.set_cookie(
        key=session_cookie_name(),
        value=session.id,
        max_age=None,  # HttpOnly session cookie — clears when the browser closes
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(session_cookie_name(), path="/")


def clear_oidc_cookie(response: Response) -> None:
    response.delete_cookie(OIDC_STATE_COOKIE, path="/")


def session_cookie_name() -> str:
    from app.core import config

    return config.settings.session_cookie
