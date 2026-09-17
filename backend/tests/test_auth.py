"""Authentication & authorization tests.

Covers the two guarantees of the OIDC design:
1. every product /api route requires a valid PacketKage session (fail closed);
2. roles come only from the verified Authentik ID token's group claim
   (admin → 403 for analysts on destructive endpoints; nobody → 403 everywhere).

Full OIDC code-flow tests run against a live fake provider (``oidc_provider``)
so the real HTTP discovery + token exchange is exercised.
"""

from __future__ import annotations

import json
import time
from contextlib import contextmanager
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from conftest import make_app_env, make_session_token
from fake_oidc_provider import USERS, generate_id_token, public_jwks
from fastapi.testclient import TestClient

from app.auth import jwt as jwtmod
from app.auth import sessions as sessionsmod
from app.auth.dependencies import PUBLIC_API_PATHS
from app.auth.oidc import OIDCClient
from app.db.orm import AuthSessionModel, utcnow

ISSUER = "http://oidc.test"
CLIENT_ID = "packetkage-test"
REDIRECT_URI = "http://testserver/api/auth/callback"


@contextmanager
def open_client(env, roles=None, username="tester"):
    client = TestClient(env["app"], follow_redirects=False)
    client.__enter__()
    try:
        if roles is not None:
            token = make_session_token(env, roles, username)
            client.cookies.set(env["settings"].session_cookie, token)
        yield client
    finally:
        client.__exit__(None, None, None)


# --------------------------------------------------------------------------
# Public / protected surface
# --------------------------------------------------------------------------


def _required_deps():
    # Match by name: conftest reimports the ``app.*`` modules per test, so the
    # function objects captured at collection time differ by identity from the
    # ones mounted in the freshly-built app. Names are stable, identities are not.
    # ``require_setup_access`` guards the (unconfigured) setup surface, which
    # cannot depend on a session; its own branch enforces loopback/token/admin.
    return {"get_current_user", "require_user", "require_admin", "require_setup_access"}


def _route_dep_call_names(route, chain):
    """Names of every dependency function reachable for ``route``.

    ``route.dependencies`` only carries ``dependencies=``/include-level deps;
    function-parameter ``Depends(...)`` (e.g. /api/auth/me) live in the
    ``route.dependant`` tree, so walk both.
    """
    names = {
        getattr(d, "dependency", None).__name__
        for d in chain + list(route.dependencies)
        if getattr(d, "dependency", None) is not None
    }
    stack = [route.dependant] if getattr(route, "dependant", None) else []
    while stack:
        node = stack.pop()
        call = getattr(node, "call", None)
        if call is not None:
            names.add(getattr(call, "__name__", str(call)))
        stack.extend(getattr(node, "dependencies", []) or [])
    return names


def _api_routes(app):
    """Yield (APIRoute, chain_deps) for every mounted API route.

    Starlette 1.6 wraps include_router() calls in lazy ``_IncludedRouter``
    objects, so plain ``app.routes`` APIRoute scanning misses everything but
    app-level routes like /api/health. Walk the included routers and carry the
    include-level dependencies down so structural tests see the real surface.
    """
    from fastapi.routing import APIRoute

    def walk(container, chain):
        for r in getattr(container, "routes", []):
            inc = getattr(r, "include_context", None)
            if inc is not None:
                yield from walk(inc.included_router, chain + (inc.dependencies or []))
            elif isinstance(r, APIRoute):
                yield r, chain

    yield from walk(app, [])


def test_every_product_route_carries_an_auth_dependency(app_env):
    api_routes = list(_api_routes(app_env["app"]))
    assert len(api_routes) >= 5, "expected far more than a handful of API routes"
    for route, chain in api_routes:
        if route.path in PUBLIC_API_PATHS:
            continue
        names = _route_dep_call_names(route, chain)
        message = f"{route.path} is missing an auth dependency"
        assert names & _required_deps(), message


def test_public_paths_have_no_auth_dependency(app_env):
    """The public set must stay reachable without a session; enforce it
    structurally so the OpenAPI guard can't accidentally regress."""
    public_routes = [(r, chain) for r, chain in _api_routes(app_env["app"]) if r.path in PUBLIC_API_PATHS]
    assert {r.path for r, _ in public_routes} == PUBLIC_API_PATHS
    for route, chain in public_routes:
        assert not (chain + list(route.dependencies)), f"{route.path} must not depend on auth"


def test_setup_routes_use_the_setup_guard(app_env):
    """The setup surface is the one place that can't require a session, so pin
    exactly which guard it carries (loopback/token when unconfigured, admin
    when configured)."""
    from app.setup.dependencies import SETUP_API_PATHS

    routes = {r.path: (r, chain) for r, chain in _api_routes(app_env["app"])}
    assert set(routes) >= SETUP_API_PATHS, "setup router routes are not mounted"
    for path in sorted(SETUP_API_PATHS):
        route, chain = routes[path]
        assert "require_setup_access" in _route_dep_call_names(route, chain), path


def test_public_paths_are_accessible(app_env):
    with open_client(app_env) as client:
        assert client.get("/api/health").status_code == 200
        status = client.get("/api/auth/status")
        assert status.status_code == 200
        body = status.json()
        assert body["configured"] is True
        assert body["admin_group"] == "packetkage-admin"
        assert body["analyst_group"] == "packetkage-analyst"


def test_unauthenticated_requests_return_401(app_env):
    with open_client(app_env) as client:
        for path in ("/api/captures", "/api/flows", "/api/jobs", "/api/cases", "/api/auth/me"):
            assert client.get(path).status_code == 401, path
        assert client.delete("/api/cases/nope").status_code == 401


def test_auth_disabled_fails_closed(tmp_path, monkeypatch):
    """Without PACKETKAGE_OIDC_ISSUER the API must refuse to serve, never run open."""
    env = make_app_env(tmp_path, monkeypatch, oidc=False)
    try:
        with TestClient(env["app"]) as client:
            assert client.get("/api/captures").status_code == 503
            assert client.get("/api/auth/login").status_code == 503
            assert client.get("/api/auth/status").json()["configured"] is False
            assert client.get("/api/health").status_code == 200
    finally:
        env["database"].engine.dispose()


# --------------------------------------------------------------------------
# Roles and admin gates
# --------------------------------------------------------------------------


def test_analyst_can_use_product_apis_but_not_admin_gates(app_env):
    with open_client(app_env, roles=["analyst"]) as client:
        assert client.get("/api/captures").status_code == 200
        assert client.get("/api/cases").status_code == 200
        assert client.delete("/api/cases/nope").status_code == 403
        assert client.delete("/api/captures/nope").status_code == 403


def test_admin_can_use_admin_gates(app_env):
    with open_client(app_env, roles=["admin"]) as client:
        assert client.get("/api/captures").status_code == 200
        assert client.delete("/api/cases/nope").status_code == 404  # auth OK, case missing


def test_authenticated_without_any_group_is_forbidden(app_env):
    with open_client(app_env, roles=[]) as client:
        assert client.get("/api/captures").status_code == 403
        assert client.get("/api/auth/me").json()["roles"] == []


# --------------------------------------------------------------------------
# Session lifecycle (server-side revocation, expiry, tampering)
# --------------------------------------------------------------------------


def test_logout_revokes_session(app_env):
    env = app_env
    with open_client(env, roles=["admin"]) as client:
        assert client.get("/api/captures").status_code == 200
        response = client.post("/api/auth/logout")
        assert response.status_code == 200
        assert client.get("/api/captures").status_code == 401


def test_tampered_session_token_rejected(app_env):
    with open_client(app_env) as client:
        client.cookies.set(app_env["settings"].session_cookie, "not-in-the-database")
        assert client.get("/api/captures").status_code == 401


def test_expired_session_rejected(app_env):
    env = app_env
    db = env["database"].SessionLocal()
    try:
        expired = AuthSessionModel(
            id="expired-token",
            sub="sub-expired",
            username="expired",
            email=None,
            groups=[],
            roles=["admin"],
            created_at=utcnow(),
            expires_at=utcnow() - timedelta(seconds=60),
        )
        db.add(expired)
        db.commit()
    finally:
        db.close()

    with open_client(app_env) as client:
        client.cookies.set(env["settings"].session_cookie, "expired-token")
        assert client.get("/api/captures").status_code == 401


# --------------------------------------------------------------------------
# Full OIDC authorization-code + PKCE flow
# --------------------------------------------------------------------------


def _begin_login(client, oidc_provider, next_path=None):
    params = {"next": next_path} if next_path else {}
    response = client.get("/api/auth/login", params=params)
    assert response.status_code == 302
    authorize_url = response.headers["location"]
    assert authorize_url.startswith(oidc_provider["base"])
    return authorize_url


def _authorize_and_parse(oidc_provider, authorize_url, *, user="admin", token_mode=None):
    with httpx.Client(base_url=oidc_provider["base"], follow_redirects=False) as hx:
        hx.get("/choose", params={"user": user})
        url = authorize_url + (f"&user={user}" if "user=" not in authorize_url else "")
        if token_mode:
            url += f"&token_mode={token_mode}"
        authorization = hx.get(url)
    assert authorization.status_code == 302
    callback_url = authorization.headers["location"]
    assert callback_url.startswith(REDIRECT_URI)
    params = parse_qs(urlparse(callback_url).query)
    return params["code"][0], params["state"][0]


def test_oidc_login_flow_mints_session_with_roles(app_env_with_idp, oidc_provider):
    env = app_env_with_idp
    with open_client(env) as client:
        authorize_url = _begin_login(client, oidc_provider, next_path="/flows")
        code, state = _authorize_and_parse(oidc_provider, authorize_url, user="admin")

        callback = client.get("/api/auth/callback", params={"code": code, "state": state})
        assert callback.status_code == 302
        assert callback.headers["location"] == "http://testserver/flows"

        token = client.cookies.get(env["settings"].session_cookie)
        assert token

        me = client.get("/api/auth/me")
        assert me.status_code == 200
        body = me.json()
        assert body["authenticated"] is True
        assert body["sub"] == USERS["admin"]["sub"]
        assert set(body["roles"]) == {"admin", "analyst"}
        assert set(body["groups"]) == {"packetkage-admin", "packetkage-analyst"}
        assert body["is_admin"] is True


def test_oidc_login_flow_analyst_roles(app_env_with_idp, oidc_provider):
    env = app_env_with_idp
    with open_client(env) as client:
        authorize_url = _begin_login(client, oidc_provider)
        code, state = _authorize_and_parse(oidc_provider, authorize_url, user="analyst")
        client.get("/api/auth/callback", params={"code": code, "state": state})
        body = client.get("/api/auth/me").json()
        assert body["roles"] == ["analyst"]
        assert body["is_admin"] is False

        # analyst via real IdP still can't delete
        assert client.delete("/api/cases/nope").status_code == 403


def test_oidc_from_analyst_meets_admin_gate_403(app_env_with_idp, oidc_provider):
    env = app_env_with_idp
    with open_client(env) as client:
        authorize_url = _begin_login(client, oidc_provider)
        code, state = _authorize_and_parse(oidc_provider, authorize_url, user="analyst")
        client.get("/api/auth/callback", params={"code": code, "state": state})
        assert client.delete("/api/captures/nope").status_code == 403


@pytest.mark.parametrize(
    "mode",
    ["expired", "wrong_signature", "wrong_issuer", "wrong_audience", "wrong_nonce"],
)
def test_oidc_rejects_broken_id_tokens(app_env_with_idp, oidc_provider, mode):
    env = app_env_with_idp
    with open_client(env) as client:
        authorize_url = _begin_login(client, oidc_provider)
        code, state = _authorize_and_parse(oidc_provider, authorize_url, user="admin", token_mode=mode)

        callback = client.get("/api/auth/callback", params={"code": code, "state": state})
        assert callback.status_code == 302
        assert callback.headers["location"] == "http://testserver/?login=error"
        assert client.cookies.get(env["settings"].session_cookie) is None
        assert client.get("/api/auth/me").status_code == 401


def test_oidc_rejects_state_mismatch(app_env_with_idp, oidc_provider):
    env = app_env_with_idp
    with open_client(env) as client:
        authorize_url = _begin_login(client, oidc_provider)
        code, _ = _authorize_and_parse(oidc_provider, authorize_url, user="admin")

        callback = client.get("/api/auth/callback", params={"code": code, "state": "attacker-state"})
        assert callback.headers["location"] == "http://testserver/?login=error"
        assert client.cookies.get(env["settings"].session_cookie) is None
        assert client.get("/api/auth/me").status_code == 401


def test_oidc_rejects_replayed_authorization_code(app_env_with_idp, oidc_provider):
    env = app_env_with_idp
    with open_client(env) as client:
        authorize_url = _begin_login(client, oidc_provider)
        code, state = _authorize_and_parse(oidc_provider, authorize_url, user="admin")
        callback = client.get("/api/auth/callback", params={"code": code, "state": state})
        assert callback.status_code == 302  # first exchange succeeds

        token = client.cookies.get(env["settings"].session_cookie)
        assert token
        # the provider consumed the code; replay must not mint a new session or break the existing one
        callback = client.get("/api/auth/callback", params={"code": code, "state": state})
        assert callback.headers["location"] == "http://testserver/?login=error"
        assert client.get("/api/auth/me").status_code == 200
        assert client.cookies.get(env["settings"].session_cookie) == token


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/flows", "/flows"),
        ("/flows?capture_id=abc123#top", "/flows?capture_id=abc123#top"),
        ("https://evil.example", "/"),
        ("//evil.example", "/"),
        ("/\\evil.example", "/"),
        ("/a\r\nSet-Cookie: x", "/"),
    ],
)
def test_login_sanitizes_next_parameter(app_env_with_idp, oidc_provider, raw, expected):
    env = app_env_with_idp
    with open_client(env) as client:
        client.get("/api/auth/login", params={"next": raw})
        stored = client.cookies.get("packetkage_oidc")
        assert stored
        payload = sessionsmod.decode_oidc_payload(stored)
        assert payload is not None
        assert payload["next"] == expected
        assert payload["state"] and payload["nonce"] and payload["verifier"]


# --------------------------------------------------------------------------
# ID-token verification unit tests
# --------------------------------------------------------------------------


def _token(token, **kwargs):
    return jwtmod.verify_id_token(
        token,
        public_jwks(),
        issuer=ISSUER,
        audience=CLIENT_ID,
        nonce="nonce-1",
        **kwargs,
    )


def _base_token(**overrides):
    fields = dict(
        subject="sub-1",
        username="alice",
        email="alice@packetkage.test",
        groups=["packetkage-admin"],
        issuer=ISSUER,
        client_id=CLIENT_ID,
        nonce="nonce-1",
    )
    fields.update(overrides)
    return generate_id_token(**fields)


def test_jwt_accepts_valid_id_token():
    claims = _token(_base_token())
    assert claims["sub"] == "sub-1"
    assert claims["groups"] == ["packetkage-admin"]


def test_jwt_rejects_expired():
    token = _base_token(exp_delta=-7200)
    with pytest.raises(jwtmod.JWTValidationError, match="expired"):
        _token(token)


def test_jwt_rejects_not_yet_valid():
    claims = {"nbf": int(time.time()) + 600, "iat": int(time.time())}
    token = _base_token(exp_delta=3600, extra=claims)
    with pytest.raises(jwtmod.JWTValidationError, match="not_yet_valid"):
        _token(token)


def test_jwt_rejects_bad_signature():
    token = _base_token()
    header, body, _sig = token.rsplit(".", 2)
    token = f"{header}.{body}.AAAA"
    with pytest.raises(jwtmod.JWTValidationError, match="signature"):
        _token(token)


def test_jwt_rejects_wrong_issuer():
    token = _base_token(issuer_override="http://evil.test")
    with pytest.raises(jwtmod.JWTValidationError, match="issuer"):
        _token(token)


def test_jwt_accepts_issuer_with_trailing_slash():
    # Authentik advertises the issuer with a trailing slash; that must not
    # be treated as a different issuer.
    token = _base_token(issuer_override=f"{ISSUER}/")
    claims = _token(token)
    assert claims["iss"] == f"{ISSUER}/"


def test_oidc_discovery_accepts_issuer_with_trailing_slash():
    import asyncio

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "issuer": f"{ISSUER}/",
                "authorization_endpoint": f"{ISSUER}/authorize",
                "token_endpoint": f"{ISSUER}/token",
                "jwks_uri": f"{ISSUER}/jwks",
            },
        )

    async def fetch() -> dict:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as hx:
            client = OIDCClient(
                issuer=ISSUER,
                client_id=CLIENT_ID,
                client_secret="secret",
                redirect_uri="http://localhost/api/auth/callback",
                http=hx,
            )
            return await client.metadata()

    assert asyncio.run(fetch())["issuer"] == f"{ISSUER}/"


def test_jwt_rejects_wrong_audience():
    token = _base_token(audience=["some-other-client"])
    with pytest.raises(jwtmod.JWTValidationError, match="does not include"):
        _token(token)


def test_jwt_rejects_wrong_nonce():
    token = _base_token(nonce="attacker-nonce")
    with pytest.raises(jwtmod.JWTValidationError, match="nonce"):
        _token(token)


def test_jwt_rejects_alg_none():
    import base64

    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    claims = b64url(
        json.dumps({"iss": ISSUER, "sub": "sub-1", "aud": CLIENT_ID, "exp": int(time.time()) + 300}).encode()
    )
    with pytest.raises(jwtmod.JWTValidationError):
        _token(f"{header}.{claims}.")


def test_jwt_rejects_garbage():
    with pytest.raises(jwtmod.JWTValidationError):
        _token("not-a-jwt")
