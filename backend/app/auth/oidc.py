"""OpenID Connect client for the Authentik authorization-code + PKCE flow.

Responsibilities:
* discovery (``.well-known/openid-configuration``) with issuer pinning
* JWKS fetching with a short TTL cache (keys rotate occasionally)
* authorize-URL construction with state / nonce / S256 PKCE challenge
* token exchange (``authorization_code``) with ``code_verifier``
* ID-token verification (signature + iss/aud/azp/nonce/exp/nbf) and group→role mapping

All HTTP is performed by the caller-supplied AsyncClient facade so tests can
run the client against mock/fake transports without real DNS.
"""

from __future__ import annotations

import base64
import hashlib
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode

import httpx

from app.auth import jwt as jwtmod

_DISCOVERY_PATH = "/.well-known/openid-configuration"
_JWKS_CACHE_TTL = 300.0  # seconds


class OIDCError(RuntimeError):
    """An OIDC interaction failed. ``stage`` ∈ {config, discovery, jwks, token, id_token}."""

    def __init__(self, stage: str, message: str):
        super().__init__(message)
        self.stage = stage


class OIDCClient:
    def __init__(
        self,
        *,
        issuer: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scope: str = "openid profile email",
        groups_claim: str = "groups",
        admin_group: str = "packetkage-admin",
        analyst_group: str = "packetkage-analyst",
        http: httpx.AsyncClient | None = None,
        machine_now: Callable[[], float] | None = None,
    ):
        if not issuer or not client_id or not redirect_uri:
            raise OIDCError("config", "OIDC is not fully configured (issuer/client_id/redirect_uri required)")
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scope = scope if "openid" in scope.split() else f"openid {scope}"
        self.groups_claim = groups_claim
        self.admin_group = admin_group
        self.analyst_group = analyst_group
        self._http = http or httpx.AsyncClient(timeout=15.0)
        self._metadata: dict[str, Any] | None = None
        self._jwks: dict[str, Any] | None = None
        self._jwks_at = 0.0
        self._now = machine_now or time.time

    # ---- discovery --------------------------------------------------------
    async def metadata(self) -> dict[str, Any]:
        if self._metadata is None:
            url = f"{self.issuer}{_DISCOVERY_PATH}"
            try:
                resp = await self._http.get(url, headers={"Accept": "application/json"})
                resp.raise_for_status()
                doc = resp.json()
            except (httpx.HTTPError, ValueError) as exc:
                raise OIDCError("discovery", f"OIDC discovery failed for {url!r}: {exc}") from exc
            # Authentik (and some other IdPs) advertise the issuer with a
            # trailing slash. Compare normalized so a slash-only difference
            # does not break an otherwise exact match.
            if str(doc.get("issuer") or "").rstrip("/") != self.issuer:
                raise OIDCError(
                    "discovery",
                    f"Discovery issuer {doc.get('issuer')!r} does not match configured issuer {self.issuer!r}",
                )
            for endpoint in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                if not doc.get(endpoint):
                    raise OIDCError("discovery", f"Discovery document missing {endpoint!r}")
            self._metadata = doc
        return self._metadata

    async def jwks(self) -> dict[str, Any]:
        now = self._now()
        if self._jwks is None or now - self._jwks_at > _JWKS_CACHE_TTL:
            uri = (await self.metadata())["jwks_uri"]
            try:
                resp = await self._http.get(uri, headers={"Accept": "application/json"})
                resp.raise_for_status()
                doc = resp.json()
            except (httpx.HTTPError, ValueError) as exc:
                raise OIDCError("jwks", f"JWKS fetch failed for {uri!r}: {exc}") from exc
            if not doc.get("keys"):
                raise OIDCError("jwks", f"JWKS document from {uri!r} contains no keys")
            self._jwks = doc
            self._jwks_at = now
        return self._jwks

    # ---- authorization request -------------------------------------------
    @staticmethod
    def generate_code_verifier() -> str:
        # 64 random chars, [A-Za-z0-9_-] — well inside the 43..128 spec window.
        import secrets

        return secrets.token_urlsafe(48)

    @staticmethod
    def pkce_challenge(verifier: str) -> str:
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    @staticmethod
    def generate_state() -> str:
        import secrets

        return secrets.token_urlsafe(32)

    @staticmethod
    def generate_nonce() -> str:
        import secrets

        return secrets.token_urlsafe(32)

    async def authorize_url(self, *, state: str, nonce: str, code_verifier: str) -> str:
        meta = await self.metadata()
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": self.pkce_challenge(code_verifier),
            "code_challenge_method": "S256",
        }
        return f"{meta['authorization_endpoint']}?{urlencode(params)}"

    # ---- token exchange ----------------------------------------------------
    async def exchange(
        self,
        *,
        code: str,
        code_verifier: str,
        nonce: str,
    ) -> tuple[dict[str, Any], str]:
        """Exchange the authorization code and validate the resulting ID token.

        Returns ``(claims, raw_id_token)``. ``state`` was already matched
        against the value we stashed in the browser's cookie by the router.
        """
        meta = await self.metadata()
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code_verifier": code_verifier,
        }
        try:
            resp = await self._http.post(
                meta["token_endpoint"],
                data=payload,
                headers={"Accept": "application/json"},
            )
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        except (httpx.HTTPError, ValueError) as exc:
            raise OIDCError("token", f"Token endpoint request failed: {exc}") from exc

        if not resp.is_success:
            error = (body or {}).get("error") or resp.text[:200]
            raise OIDCError("token", f"Token endpoint returned {resp.status_code}: {error}")

        id_token = body.get("id_token")
        if not id_token:
            raise OIDCError("token", "Token response did not include an id_token")

        jwks = await self.jwks()

        try:
            claims = jwtmod.verify_id_token(
                id_token,
                jwks,
                issuer=self.issuer,
                audience=self.client_id,
                nonce=nonce,
                now=self._now(),
            )
        except jwtmod.JWTValidationError as exc:
            raise OIDCError("id_token", f"ID token rejected: {exc.reason}") from exc

        return claims, id_token

    # ---- role mapping ------------------------------------------------------
    def roles_for(self, groups: list[Any]) -> list[str]:
        """Map Authentik group memberships to PacketKage roles.

        Accepts group names as strings or as dicts carrying a ``name`` key
        (Authentik can be configured either way). Never trusts the client:
        groups always come from the verified ID token.
        """
        names = set()
        for g in groups or []:
            if isinstance(g, str):
                names.add(g)
            elif isinstance(g, dict) and isinstance(g.get("name"), str):
                names.add(g["name"])
        return [
            r for r, group in (("admin", self.admin_group), ("analyst", self.analyst_group)) if group in names
        ]

    async def aclose(self) -> None:
        await self._http.aclose()


class _ClientCache:
    """One OIDCClient per distinct OIDC configuration.

    App modules (and Settings instances) are recreated per test, so keying by
    the settings object's id would leak. Instead, key by the configuration
    tuple — identical config reuses one client (discovery/JWKS stay cached),
    and a new config (e.g. auth disabled, different issuer) gets a new one.
    """

    def __init__(self) -> None:
        self._store: dict[tuple, OIDCClient] = {}

    def _key(self, settings) -> tuple:
        return (
            settings.oidc_issuer,
            settings.oidc_client_id,
            settings.oidc_client_secret,
            settings.oidc_redirect_uri,
            settings.oidc_scope,
            settings.oidc_groups_claim,
            settings.admin_group,
            settings.analyst_group,
        )

    def get_or_create(self, settings) -> OIDCClient:
        key = self._key(settings)
        client = self._store.get(key)
        if client is None:
            client = OIDCClient(
                issuer=settings.oidc_issuer,
                client_id=settings.oidc_client_id,
                client_secret=settings.oidc_client_secret,
                redirect_uri=settings.oidc_redirect_uri,
                scope=settings.oidc_scope,
                groups_claim=settings.oidc_groups_claim,
                admin_group=settings.admin_group,
                analyst_group=settings.analyst_group,
            )
            self._store[key] = client
        return client


_client_cache = _ClientCache()
