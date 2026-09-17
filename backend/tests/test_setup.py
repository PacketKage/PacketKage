"""First-run setup and OIDC reconfiguration tests.

Two guarantees:
1. While unconfigured, the setup surface is reachable only from loopback or with
   the one-time bootstrap token — and saving the config enables auth in the same
   process, with no restart (the full login flow then works).
2. Once configured, reconfiguration requires an authenticated admin.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
from conftest import make_app_env, make_session_token
from fastapi.testclient import TestClient

TOKEN = "setup-token-for-tests"

SAVE_BODY = {
    "oidc_issuer": "",  # filled per test from the live provider
    "oidc_client_id": "packetkage-test",
    "oidc_client_secret": "test-secret",
    "oidc_redirect_uri": "http://testserver/api/auth/callback",
    "public_url": "http://testserver",
}

AUTH = {"X-Setup-Token": TOKEN}


def _unconfigured(tmp_path, monkeypatch, **extra):
    return make_app_env(
        tmp_path,
        monkeypatch,
        oidc=False,
        extra_env={"PACKETKAGE_SETUP_TOKEN": TOKEN, **extra},
    )


def _body(provider_base: str) -> dict:
    return {**SAVE_BODY, "oidc_issuer": provider_base}


def test_client_is_loopback_detection():
    from app.setup.dependencies import client_is_loopback

    class Conn:
        def __init__(self, host: str):
            self.host = host

    class Req:
        def __init__(self, host: str):
            self.client = Conn(host)

    assert client_is_loopback(Req("127.0.0.1"))
    assert client_is_loopback(Req("::1"))
    assert not client_is_loopback(Req("10.0.0.5"))
    assert not client_is_loopback(Req("testclient"))


def test_status_is_public_and_reports_unconfigured(tmp_path, monkeypatch):
    env = _unconfigured(tmp_path, monkeypatch)
    try:
        with TestClient(env["app"], follow_redirects=False) as client:
            response = client.get("/api/setup/status")
            assert response.status_code == 200
            assert response.json() == {"configured": False, "requires_token": True}
    finally:
        env["database"].engine.dispose()


def test_config_requires_the_bootstrap_token_from_a_remote_caller(tmp_path, monkeypatch):
    env = _unconfigured(tmp_path, monkeypatch)
    try:
        with TestClient(env["app"], follow_redirects=False) as client:
            assert client.get("/api/setup/config").status_code == 403
            response = client.get("/api/setup/config", headers=AUTH)
            assert response.status_code == 200
            body = response.json()
            assert body["configured"] is False
            assert body["values"]["oidc_client_secret"] == ""  # secret never returned
    finally:
        env["database"].engine.dispose()


def test_test_endpoint_reports_discovery_failure_without_saving(tmp_path, monkeypatch):
    env = _unconfigured(tmp_path, monkeypatch)
    try:
        with TestClient(env["app"], follow_redirects=False) as client:
            response = client.post(
                "/api/setup/test",
                headers=AUTH,
                json=_body("http://127.0.0.1:9"),
            )
            assert response.status_code == 200
            body = response.json()
            assert body["ok"] is False
            assert body["stage"] == "discovery"
            # nothing was persisted/activated
            assert client.get("/api/auth/status").json()["configured"] is False
    finally:
        env["database"].engine.dispose()


def test_test_endpoint_succeeds_against_the_provider(tmp_path, monkeypatch, oidc_provider):
    env = _unconfigured(tmp_path, monkeypatch)
    try:
        with TestClient(env["app"], follow_redirects=False) as client:
            response = client.post(
                "/api/setup/test",
                headers=AUTH,
                json=_body(oidc_provider["base"]),
            )
            body = response.json()
            assert body["ok"] is True, body
            assert body["issuer"] == oidc_provider["base"]
            assert body["token_endpoint"]
    finally:
        env["database"].engine.dispose()


def test_save_enables_auth_and_login_without_restart(tmp_path, monkeypatch, oidc_provider):
    env = _unconfigured(tmp_path, monkeypatch)
    try:
        with TestClient(env["app"], follow_redirects=False) as client:
            assert client.get("/api/captures").status_code == 503  # fail closed

            saved = client.post(
                "/api/setup/oidc",
                headers=AUTH,
                json=_body(oidc_provider["base"]),
            )
            assert saved.status_code == 200, saved.text
            assert saved.json()["configured"] is True

            # same process, no restart: protected API now challenges (401), not 503
            assert client.get("/api/captures").status_code == 401
            assert client.get("/api/auth/status").json()["configured"] is True

            # the full authorization-code + PKCE flow works against the saved config
            login = client.get("/api/auth/login")
            assert login.status_code == 302
            authorize_url = login.headers["location"]
            assert authorize_url.startswith(oidc_provider["base"])

            with httpx.Client(base_url=oidc_provider["base"], follow_redirects=False) as hx:
                hx.get("/choose", params={"user": "admin"})
                url = authorize_url + ("&user=admin" if "user=" not in authorize_url else "")
                authorization = hx.get(url)
            callback_url = authorization.headers["location"]
            params = parse_qs(urlparse(callback_url).query)

            callback = client.get(
                "/api/auth/callback",
                params={"code": params["code"][0], "state": params["state"][0]},
            )
            assert callback.status_code == 302
            me = client.get("/api/auth/me")
            assert me.status_code == 200
            assert me.json()["is_admin"] is True
    finally:
        env["database"].engine.dispose()


def test_save_persists_to_disk_owner_only_and_reloads(tmp_path, monkeypatch, oidc_provider):
    env = _unconfigured(tmp_path, monkeypatch)
    try:
        with TestClient(env["app"], follow_redirects=False) as client:
            assert (
                client.post("/api/setup/oidc", headers=AUTH, json=_body(oidc_provider["base"])).status_code
                == 200
            )

        from app.core import config as configmod

        setup_path = configmod.settings.setup_file
        assert setup_path.exists()
        assert setup_path.stat().st_mode & 0o777 == 0o600

        # a fresh Settings object (e.g. next process) picks the file back up
        reloaded = configmod.Settings(database_url="sqlite:///:memory:", upload_dir=env["upload_dir"])
        assert reloaded.auth_enabled is False
        assert reloaded.apply_persisted() is True
        assert reloaded.auth_enabled is True
        assert reloaded.oidc_client_id == "packetkage-test"
        assert reloaded.oidc_redirect_uri == "http://testserver/api/auth/callback"
    finally:
        env["database"].engine.dispose()


def test_env_managed_fields_cannot_be_overwritten(tmp_path, monkeypatch):
    env = _unconfigured(tmp_path, monkeypatch, PACKETKAGE_PUBLIC_URL="http://locked.test")
    try:
        with TestClient(env["app"], follow_redirects=False) as client:
            response = client.post(
                "/api/setup/oidc",
                headers=AUTH,
                json={"public_url": "http://evil.test"},
            )
            assert response.status_code == 409
            assert "public_url" in response.json()["detail"]
    finally:
        env["database"].engine.dispose()


def test_reconfiguration_requires_an_admin_session(app_env):
    env = app_env  # OIDC is configured via the environment
    with TestClient(env["app"], follow_redirects=False) as client:
        assert client.get("/api/setup/config").status_code == 401  # anonymous

    with TestClient(env["app"], follow_redirects=False) as client:
        client.cookies.set(env["settings"].session_cookie, make_session_token(env, ["analyst"]))
        assert client.get("/api/setup/config").status_code == 403  # analyst

    with TestClient(env["app"], follow_redirects=False) as client:
        client.cookies.set(env["settings"].session_cookie, make_session_token(env, ["admin"]))
        response = client.get("/api/setup/config")
        assert response.status_code == 200
        body = response.json()
        assert "oidc_issuer" in body["locked"]
        assert body["values"]["oidc_client_secret"] == ""


def test_admin_can_reconfigure_an_unlocked_field(app_env):
    env = app_env
    with TestClient(env["app"], follow_redirects=False) as client:
        client.cookies.set(env["settings"].session_cookie, make_session_token(env, ["admin"]))
        response = client.post("/api/setup/oidc", json={"admin_group": "custom-admins"})
        assert response.status_code == 200, response.text
        assert env["settings"].admin_group == "custom-admins"
        assert client.get("/api/setup/config").json()["values"]["admin_group"] == "custom-admins"
