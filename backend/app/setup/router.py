"""First-run setup and reconfiguration endpoints.

Routes:
* ``GET  /api/setup/status`` — public: is OIDC configured, does this caller need
  the bootstrap token. Drives whether the UI shows the setup wizard.
* ``GET  /api/setup/config`` — current settings + which fields env has locked
  (secret never returned). Guarded by :func:`require_setup_access`.
* ``POST /api/setup/test``   — OIDC discovery + JWKS pre-flight for the values
  the operator typed, without saving them.
* ``POST /api/setup/oidc``   — validate, persist to the data volume and apply to
  the live settings (no restart); enabled on the next request.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.auth.oidc import OIDCClient, OIDCError
from app.core import config
from app.setup.dependencies import client_is_loopback, require_setup_access

router = APIRouter(prefix="/api/setup", tags=["setup"])

_DEFAULT_SCOPE = "openid profile email"


class SetupConfig(BaseModel):
    """Submitted OIDC settings — every field optional so partial updates work."""

    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = ""
    public_url: str = ""
    oidc_scope: str = ""
    oidc_groups_claim: str = ""
    admin_group: str = ""
    analyst_group: str = ""

    def values(self) -> dict[str, str]:
        return {
            key: value.strip()
            for key, value in self.model_dump().items()
            if isinstance(value, str) and value.strip()
        }


@router.get("/status")
def setup_status(request: Request) -> dict:
    settings = config.settings
    return {
        "configured": settings.auth_enabled,
        "requires_token": not client_is_loopback(request),
    }


@router.get("/config")
def read_configuration(_: object = Depends(require_setup_access)) -> dict:
    settings = config.settings
    values: dict[str, str] = {}
    for name in config.SETUP_FIELDS:
        # Never return the client secret; the UI only needs to know if it is set.
        values[name] = "" if name == "oidc_client_secret" else str(getattr(settings, name))
    return {
        "configured": settings.auth_enabled,
        "values": values,
        "locked": sorted(settings.env_locked_fields()),
        "client_secret_set": bool(settings.oidc_client_secret),
        "persisted": bool(config.load_setup_file(settings.setup_file)),
    }


@router.post("/test")
async def test_configuration(
    body: SetupConfig,
    _: object = Depends(require_setup_access),
) -> dict:
    values = body.values()
    issuer = values.get("oidc_issuer", "").rstrip("/")
    client_id = values.get("oidc_client_id", "")
    public_url = values.get("public_url", "").rstrip("/")
    redirect_uri = values.get("oidc_redirect_uri", "")
    if not redirect_uri and public_url:
        redirect_uri = f"{public_url}/api/auth/callback"

    if not issuer or not client_id or not redirect_uri:
        return {
            "ok": False,
            "stage": "config",
            "detail": "Issuer URL, client ID and redirect URI are required.",
        }

    client = OIDCClient(
        issuer=issuer,
        client_id=client_id,
        client_secret=values.get("oidc_client_secret", ""),
        redirect_uri=redirect_uri,
        scope=values.get("oidc_scope") or _DEFAULT_SCOPE,
    )
    try:
        metadata = await client.metadata()
        await client.jwks()
    except OIDCError as exc:
        return {"ok": False, "stage": exc.stage, "detail": str(exc)}
    finally:
        await client.aclose()

    return {
        "ok": True,
        "issuer": metadata.get("issuer"),
        "authorization_endpoint": metadata.get("authorization_endpoint"),
        "token_endpoint": metadata.get("token_endpoint"),
        "jwks_uri": metadata.get("jwks_uri"),
    }


@router.post("/oidc")
def save_configuration(
    body: SetupConfig,
    _: object = Depends(require_setup_access),
) -> dict:
    settings = config.settings
    values = body.values()
    locked = settings.env_locked_fields()

    conflicts = sorted(
        name for name, value in values.items() if name in locked and getattr(settings, name) != value
    )
    if conflicts:
        raise HTTPException(
            409,
            "These settings are managed by environment variables and cannot be changed here: "
            + ", ".join(conflicts),
        )

    update = {name: value for name, value in values.items() if name not in locked}
    if not settings.auth_enabled:
        if not (update.get("oidc_client_secret") or settings.oidc_client_secret):
            raise HTTPException(400, "A client secret is required to enable authentication.")
        if not (update.get("oidc_issuer") or settings.oidc_issuer):
            raise HTTPException(400, "An issuer URL is required to enable authentication.")
        if not (update.get("oidc_client_id") or settings.oidc_client_id):
            raise HTTPException(400, "A client ID is required to enable authentication.")

    settings.persist_setup(update)
    settings.apply_values(update)
    settings.ensure_dirs()
    return {
        "configured": settings.auth_enabled,
        "applied": sorted(update),
        "redirect_uri": settings.oidc_redirect_uri,
    }
