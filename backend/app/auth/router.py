"""OIDC authorization-code + PKCE endpoints wired to the FastAPI app.

Routes:
* ``GET  /api/auth/status``   — is OIDC configured (used by clients to decide UX)
* ``GET  /api/auth/login``    — redirect to Authentik (state/nonce/verifier in a short-lived cookie)
* ``GET  /api/auth/callback`` — exchange code → verify id_token → mint HttpOnly session cookie
* ``GET  /api/auth/me``       — current identity + roles (401 when not logged in)
* ``POST /api/auth/logout``   — revoke the server session and clear the cookie
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.auth import sessions
from app.auth.dependencies import AuthUser, get_current_user
from app.auth.oidc import OIDCClient, OIDCError
from app.auth.rate_limit import rate_limit_callback, rate_limit_login
from app.core import config
from app.core.database import get_db

router = APIRouter(prefix="/api/auth", tags=["auth"])

_LOGIN_FAIL_PATH = "/?login=error"


def get_oidc_client(settings) -> OIDCClient:
    from app.auth.oidc import _client_cache

    return _client_cache.get_or_create(settings)


def _cookie_secure() -> bool:
    s = config.settings
    if s.session_secure_cookie is not None:
        return bool(s.session_secure_cookie)
    return s.oidc_redirect_uri.startswith("https://") or s.public_url.startswith("https://")


def _safe_next(raw: str | None) -> str:
    """Allow only same-origin relative paths (no ``//`` scheme hijack, no CR/LF)."""
    if not raw:
        return "/"
    raw = raw[:512]
    if not raw.startswith("/") or raw.startswith("//"):
        return "/"
    if any(ch in raw for ch in "\r\n\t\\"):
        return "/"
    return raw


def _app_origin(request: Request) -> str:
    s = config.settings
    if s.public_url:
        return s.public_url.rstrip("/")
    return str(request.base_url).rstrip("/")


def _fail_redirect(request: Request) -> RedirectResponse:
    return RedirectResponse(f"{_app_origin(request)}{_LOGIN_FAIL_PATH}", status_code=302)


@router.get("/status")
def auth_status() -> dict:
    s = config.settings
    return {
        "configured": s.auth_enabled,
        "issuer": s.oidc_issuer or None,
        "admin_group": s.admin_group,
        "analyst_group": s.analyst_group,
    }


@router.get("/login")
async def login(
    request: Request,
    next: str = Query(default="/"),
    _rl: None = Depends(rate_limit_login),
) -> RedirectResponse:
    s = config.settings
    if not s.auth_enabled:
        raise HTTPException(
            503,
            "Authentication is not configured — set PACKETKAGE_OIDC_ISSUER.",
        )

    client = get_oidc_client(s)
    state, nonce, verifier = (
        client.generate_state(),
        client.generate_nonce(),
        client.generate_code_verifier(),
    )
    try:
        url = await client.authorize_url(state=state, nonce=nonce, code_verifier=verifier)
    except OIDCError as exc:
        raise HTTPException(500, f"Failed to contact identity provider: {exc}") from exc

    safe_next = _safe_next(next)
    response = RedirectResponse(url, status_code=302)
    response.delete_cookie(sessions.OIDC_STATE_COOKIE, path="/")
    response.set_cookie(
        key=sessions.OIDC_STATE_COOKIE,
        value=sessions.encode_oidc_payload(
            {"state": state, "nonce": nonce, "verifier": verifier, "next": safe_next}
        ),
        max_age=900,
        httponly=True,
        secure=_cookie_secure(),
        samesite="lax",
        path="/",
    )
    return response


@router.get("/callback")
async def callback(
    request: Request,
    code: str = Query(default=""),
    state: str = Query(default=""),
    error: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _rl: None = Depends(rate_limit_callback),
) -> RedirectResponse:
    s = config.settings
    if error:
        return _fail_redirect(request)

    stored = _read_oidc_payload(request)
    if stored is None or not code or not state or state != stored["state"]:
        # State mismatch or a missing/forged callback — do not complete the login.
        return _fail_redirect(request)

    client = get_oidc_client(s)
    try:
        claims, _id_token = await client.exchange(
            code=code,
            code_verifier=stored["verifier"],
            nonce=stored["nonce"],
        )
    except OIDCError:
        return _fail_redirect(request)

    groups = _claims_groups(claims, s.oidc_groups_claim)
    roles = client.roles_for(groups)
    session = sessions.create_session(
        db,
        sub=str(claims.get("sub", "")),
        username=_claim_username(claims),
        email=_optional_str(claims.get("email")),
        groups=sorted(set(groups)),
        roles=roles,
        ttl_seconds=s.session_ttl_seconds,
    )

    response = RedirectResponse(f"{_app_origin(request)}{stored['next']}", status_code=302)
    sessions.clear_oidc_cookie(response)
    sessions.set_session_cookie(response, session, secure=_cookie_secure())
    return response


@router.get("/me")
def me(user: AuthUser = Depends(get_current_user)) -> dict:
    return user.to_dict()


@router.post("/logout")
def logout(
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    token = request.cookies.get(config.settings.session_cookie)
    if token:
        sessions.revoke_session(db, token)
    return {"ok": True}


def _read_oidc_payload(request: Request) -> dict[str, Any] | None:
    raw = request.cookies.get(sessions.OIDC_STATE_COOKIE)
    if not raw:
        return None
    payload = sessions.decode_oidc_payload(raw)
    if payload is None:
        return None
    if not all(isinstance(payload.get(k), str) for k in ("state", "nonce", "verifier")):
        return None
    return payload


def _claims_groups(claims: dict, claim_name: str) -> list[Any]:
    return claims.get(claim_name) or []


def _claim_username(claims: dict) -> str:
    for key in ("preferred_username", "username", "nickname", "email", "sub"):
        value = claims.get(key)
        if isinstance(value, str) and value:
            return value[:255]
    return "unknown-user"


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None
