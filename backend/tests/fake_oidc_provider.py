"""A minimal in-memory OpenID Connect provider used by pytest and e2e tests.

Serves discovery, JWKS, /authorize (authorization-code + PKCE), /token and a
/choose endpoint that picks which "user" (and therefore which group claim) the
provider must emit. The user is chosen either via:

* ``GET /choose?user=admin|analyst|nobody`` (sets a cookie), or
* ``?user=...`` on the authorize URL.

The ``?token_mode=`` authorize query param lets auth tests request deliberately
broken ID tokens (expired / wrong signature / wrong issuer / wrong audience /
wrong nonce) through the *real* /token endpoint, so the rejection path is
exercised end-to-end.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from typing import Any
from urllib.parse import parse_qs

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

KID = "fake-kid"
USER_KEY = "pk_fake_user"
DEFAULT_ISSUER = os.environ.get("FAKE_OIDC_ISSUER", "http://oidc.test")

USERS: dict[str, dict[str, Any]] = {
    "admin": {
        "sub": "00000000-0000-0000-0000-000000000001",
        "preferred_username": "admin@packetkage.test",
        "email": "admin@packetkage.test",
        "groups": ["packetkage-admin", "packetkage-analyst"],
    },
    "analyst": {
        "sub": "00000000-0000-0000-0000-000000000002",
        "preferred_username": "analyst@packetkage.test",
        "email": "analyst@packetkage.test",
        "groups": ["packetkage-analyst"],
    },
    "nobody": {
        "sub": "00000000-0000-0000-0000-000000000003",
        "preferred_username": "nobody@packetkage.test",
        "email": "nobody@packetkage.test",
        "groups": [],
    },
}

_KEYS: dict[str, Any] = {}
_ATTACKER_KEY: Any = None


def _ensure_keys() -> None:
    global _ATTACKER_KEY, _KEYS
    if not _KEYS:
        _KEYS["default"] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if _ATTACKER_KEY is None:
        _ATTACKER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


_ensure_keys()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_id_token(
    *,
    subject: str,
    username: str,
    email: str,
    groups: list[str],
    issuer: str,
    client_id: str,
    nonce: str | None,
    key: Any = None,
    exp_delta: int = 300,
    audience: list[str] | None = None,
    issuer_override: str | None = None,
    now: int | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    """Build and sign a fake RS256 ID token (also used to forge failures)."""
    _ensure_keys()
    key = key or _KEYS["default"]
    now = now or int(time.time())
    claims: dict[str, Any] = {
        "iss": issuer_override or issuer,
        "sub": subject,
        "aud": audience or [client_id],
        "azp": client_id or "",
        "iat": now,
        "nbf": now - 5,
        "exp": now + exp_delta,
        "preferred_username": username,
        "email": email,
        "groups": groups,
    }
    if nonce is not None:
        claims["nonce"] = nonce
    if extra:
        claims.update(extra)
    header = {"alg": "RS256", "typ": "JWT", "kid": KID}
    header_enc = b64url(json.dumps(header, separators=(",", ":")).encode())
    claims_enc = b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header_enc}.{claims_enc}".encode()
    signature = key.sign(signing_input, asym_padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input.decode()}.{b64url(signature)}"


def public_jwks() -> dict[str, Any]:
    _ensure_keys()
    public_numbers = _KEYS["default"].public_key().public_numbers()
    n_bits = public_numbers.n.bit_length()
    e_bits = public_numbers.e.bit_length()
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": KID,
                "use": "sig",
                "alg": "RS256",
                "n": b64url(public_numbers.n.to_bytes((n_bits + 7) // 8, "big")),
                "e": b64url(public_numbers.e.to_bytes((e_bits + 7) // 8, "big")),
            }
        ]
    }


def create_app(
    *,
    issuer: str = DEFAULT_ISSUER,
    client_id: str = os.environ.get("FAKE_OIDC_CLIENT_ID", "packetkage-test"),
    client_secret: str = os.environ.get("FAKE_OIDC_CLIENT_SECRET", "test-secret"),
    redirect_uris: list[str] | None = None,
) -> FastAPI:
    """Build the fake provider ASGI app."""
    redirect_uris = redirect_uris or [
        os.environ.get("FAKE_OIDC_REDIRECT_URI", "http://testserver/api/auth/callback")
    ]
    codes: dict[str, dict[str, Any]] = {}

    app = FastAPI(title="fake-oidc-provider")

    def _user(request: Request) -> dict[str, Any]:
        name = request.cookies.get(USER_KEY) or request.query_params.get("user") or "admin"
        return USERS.get(name, USERS["nobody"])

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/choose")
    def choose(response: Response, user: str = Query(default="admin")) -> dict:
        choice = user if user in USERS else "nobody"
        response.set_cookie(USER_KEY, choice, path="/")
        return {"user": choice, "groups": USERS[choice]["groups"]}

    @app.get("/.well-known/openid-configuration")
    def discovery() -> dict:
        return {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "jwks_uri": f"{issuer}/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256"],
        }

    @app.get("/jwks")
    def jwks() -> dict:
        return public_jwks()

    @app.get("/authorize")
    def authorize(request: Request) -> Response:
        params = parse_qs(str(request.url.query))
        _require(params, "client_id", client_id)
        _require(params, "response_type", "code")
        if _require(params, "code_challenge_method") != "S256":
            raise HTTPException(400, "code_challenge_method must be S256")
        redirect_uri = _require(params, "redirect_uri")
        if redirect_uri not in redirect_uris:
            raise HTTPException(400, "redirect_uri not registered")
        state = params.get("state", [""])[0]
        nonce = params.get("nonce", [None])[0] or None
        challenge = _require(params, "code_challenge")

        token_mode = params.get("token_mode", ["valid"])[0]
        if token_mode not in _TOKEN_MODES:
            token_mode = "valid"

        user = _user(request)
        code = "fake-" + secrets.token_urlsafe(24)
        codes[code] = {"user": user, "challenge": challenge, "nonce": nonce, "mode": token_mode}

        return RedirectResponse(f"{redirect_uri}?code={code}&state={state}", status_code=302)

    @app.post("/token")
    async def token(request: Request) -> JSONResponse:
        form = await request.form()
        code = str(form.get("code", ""))
        record = codes.pop(code, None)
        if record is None:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        if form.get("client_id") != client_id:
            return JSONResponse({"error": "invalid_client"}, status_code=401)
        if str(form.get("grant_type", "")) != "authorization_code":
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
        if form.get("redirect_uri") and form["redirect_uri"] not in redirect_uris:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "redirect_uri mismatch"}, status_code=400
            )

        verifier = str(form.get("code_verifier", ""))
        digest = b64url(hashlib.sha256(verifier.encode()).digest())
        if not secrets.compare_digest(digest, record["challenge"]):
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "PKCE mismatch"}, status_code=400
            )

        user = record["user"]
        mode = _TOKEN_MODES[record["mode"]]
        id_token = generate_id_token(
            subject=user["sub"],
            username=user["preferred_username"],
            email=user["email"],
            groups=list(user["groups"]),
            issuer=issuer,
            client_id=client_id,
            nonce=mode.get("nonce_override", record["nonce"]),
            exp_delta=mode.get("exp_delta", 300),
            issuer_override=mode.get("issuer_override"),
            audience=mode.get("audience_override"),
            key=_ATTACKER_KEY if mode.get("attacker_key") else _KEYS["default"],
        )
        return JSONResponse(
            {
                "access_token": "fake-access",
                "token_type": "Bearer",
                "expires_in": 300,
                "id_token": id_token,
            }
        )

    return app


_TOKEN_MODES: dict[str, dict[str, Any]] = {
    "valid": {},
    "expired": {"exp_delta": -3600},
    "wrong_signature": {"attacker_key": True},
    "wrong_issuer": {"issuer_override": "http://evil.test"},
    "wrong_audience": {"audience_override": ["other-client"]},
    "wrong_nonce": {"nonce_override": "attacker-nonce"},
}


def _require(params: dict[str, list[str]], name: str, expected: str | None = None) -> str:
    values = params.get(name) or []
    value = values[0] if values else ""
    if not value:
        raise HTTPException(400, f"missing {name}")
    if expected is not None and value != expected:
        raise HTTPException(400, f"expected {name}={expected}, got {value!r}")
    return value


def load_private_key_pem(key_id: str = "default") -> bytes:
    """Expose the signer key PEM (used by e2e config / debugging)."""
    _ensure_keys()
    if key_id == "attacker":
        return _ATTACKER_KEY.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    return _KEYS["default"].private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
