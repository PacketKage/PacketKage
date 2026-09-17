"""Access control for the first-run setup / reconfiguration endpoints.

Two states, two guards:

* **Unconfigured** — no OIDC provider yet, so there is no session to authenticate
  with. Allowed from loopback, or from anywhere holding the one-time bootstrap
  token (``X-Setup-Token`` header or ``?token=``).
* **Configured** — reconfiguration is a privileged change and requires an
  authenticated ``packetkage-admin`` session (analysts get 403).

The router itself is mounted without the product-API auth dependency, so these
endpoints are the only place that must enforce this branch themselves.
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth.dependencies import AuthUser, get_current_user
from app.core import config
from app.core.database import get_db

# Setup endpoints that carry ``require_setup_access`` (asserted structurally).
SETUP_API_PATHS = {"/api/setup/config", "/api/setup/test", "/api/setup/oidc"}

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1"}


def client_is_loopback(request: Request) -> bool:
    client = request.client
    return bool(client and client.host in _LOOPBACK_HOSTS)


def _supplied_token(request: Request) -> str:
    return request.headers.get("X-Setup-Token") or request.query_params.get("token") or ""


def require_setup_access(request: Request, db: Session = Depends(get_db)) -> AuthUser | None:
    settings = config.settings

    if settings.auth_enabled:
        # Reconfiguration: must be an authenticated administrator.
        user = get_current_user(request, db)
        if not user.is_admin:
            raise HTTPException(
                403,
                "Administrator privileges (packetkage-admin group) are required to change "
                "authentication settings.",
            )
        return user

    # First-run: loopback, or the one-time bootstrap token.
    if client_is_loopback(request):
        return None
    from app.setup.token import token_matches

    if token_matches(_supplied_token(request)):
        return None
    raise HTTPException(
        403,
        "A setup token is required to configure authentication from a remote address. "
        "Read it from the backend logs or the data volume (setup-token file).",
    )
