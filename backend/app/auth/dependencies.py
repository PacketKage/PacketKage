"""FastAPI dependencies that enforce the Authentik-backed authorization model.

Layering:
* ``get_current_user`` — resolves the session cookie to an identity. 401 if
  the session is absent/invalid/expired; 503 if OIDC isn't configured (fail
  closed — PacketKage must never silently serve without an IdP).
* ``require_user`` — "normal product API" gate: the user must be a member of
  at least one PacketKage group (admin or analyst).
* ``require_admin`` — administration gate: only ``packetkage-admin`` members.
  An authenticated analyst (or a non-member) gets a 403 here.

Roles are derived solely from the verified ID token's group claim; a role
submitted by the frontend is never consulted.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth import sessions
from app.core import config
from app.core.database import get_db

ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"

# Calls that never require a session: health, the OIDC front-channel
# (login + callback), logout/status, and the public setup-status probe the UI
# uses to decide whether to show the first-run wizard.
PUBLIC_API_PATHS = {
    "/api/health",
    "/api/auth/login",
    "/api/auth/callback",
    "/api/auth/logout",
    "/api/auth/status",
    "/api/setup/status",
}


@dataclass
class AuthUser:
    """Identity and roles attached to a valid application session."""

    sub: str
    username: str
    email: str | None
    groups: list[str]
    roles: list[str] = field(default_factory=list)

    @classmethod
    def from_session(cls, db_session: Session) -> AuthUser:
        return cls(
            sub=db_session.sub,
            username=db_session.username,
            email=db_session.email,
            groups=list(db_session.groups or []),
            roles=list(db_session.roles or []),
        )

    @property
    def is_admin(self) -> bool:
        return ROLE_ADMIN in self.roles

    def to_dict(self) -> dict:
        return {
            "authenticated": True,
            "sub": self.sub,
            "username": self.username,
            "email": self.email,
            "groups": self.groups,
            "roles": self.roles,
            "is_admin": self.is_admin,
        }


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> AuthUser:
    settings = config.settings
    if not settings.auth_enabled:
        raise HTTPException(
            503,
            "Authentication is not configured — set PACKETKAGE_OIDC_ISSUER before serving the API.",
        )

    token = request.cookies.get(settings.session_cookie)
    if not token:
        raise HTTPException(401, "Not authenticated")

    record = sessions.lookup_session(db, token)
    if record is None or not sessions.session_is_valid(record):
        raise HTTPException(401, "Session is invalid or has expired")

    return AuthUser.from_session(record)


def require_user(user: AuthUser = Depends(get_current_user)) -> AuthUser:
    """Gate for normal product APIs: any PacketKage group membership."""
    if not user.roles:
        raise HTTPException(
            403,
            "Your account is not a member of the packetkage-analyst or packetkage-admin group.",
        )
    return user


def require_admin(user: AuthUser = Depends(get_current_user)) -> AuthUser:
    """Gate for administration-only APIs: packetkage-admin membership."""
    if not user.is_admin:
        raise HTTPException(
            403,
            "Administrator privileges (packetkage-admin group) are required.",
        )
    return user
