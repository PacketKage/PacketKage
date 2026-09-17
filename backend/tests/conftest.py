"""Shared test fixtures: temp DB, client, generated PCAPs."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = BACKEND_ROOT.parent / "scripts"
TESTDATA = BACKEND_ROOT.parent / "test-data" / "synthetic"

# With OIDC configured (the default for tests), every non-public /api route
# demands a valid packetkage session — so fixtures pre-auth as an admin.
OIDC_TEST_ENV = {
    "PACKETKAGE_OIDC_ISSUER": "http://oidc.test",
    "PACKETKAGE_OIDC_CLIENT_ID": "packetkage-test",
    "PACKETKAGE_OIDC_CLIENT_SECRET": "test-secret",
    "PACKETKAGE_OIDC_REDIRECT_URI": "http://testserver/api/auth/callback",
    "PACKETKAGE_PUBLIC_URL": "http://testserver",
}


@pytest.fixture(scope="session", autouse=True)
def generated_pcaps():
    """Ensure deterministic synthetic PCAPs exist before tests run."""
    if not TESTDATA.exists() or not any(TESTDATA.glob("*.pcap")):
        import subprocess

        subprocess.run(
            [sys.executable, str(SCRIPTS / "generate_test_pcaps.py"), "--out", str(TESTDATA)],
            check=True,
            capture_output=True,
        )
    return TESTDATA


def make_app_env(tmp_path, monkeypatch, *, oidc=True, extra_env=None) -> dict:
    """Build an isolated DB + upload dir + reimported app for one test.

    ``oidc=False`` yields an app with ``PACKETKAGE_OIDC_ISSUER`` absent (auth
    disabled → the API must fail closed with 503). ``extra_env`` lets tests
    override any PacketKage env var before the app is (re)imported.
    """
    db_path = tmp_path / "test.db"
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("PACKETKAGE_DB", f"sqlite:///{db_path}")
    monkeypatch.setenv("PACKETKAGE_UPLOAD_DIR", str(upload_dir))
    if oidc:
        for key, value in OIDC_TEST_ENV.items():
            monkeypatch.setenv(key, value)
    for key, value in (extra_env or {}).items():
        monkeypatch.setenv(key, value)

    # Reimport config/engine with patched env
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]

    from app.core import config, database
    from app.main import app as fastapi_app

    importlib.reload(config)
    settings = config.Settings(database_url=f"sqlite:///{db_path}", upload_dir=upload_dir)
    config.settings = settings
    database.engine = database.make_engine(settings.database_url)
    database.SessionLocal.configure(bind=database.engine)  # type: ignore[attr-defined]
    from app.core.database import Base

    Base.metadata.create_all(bind=database.engine)
    return {
        "app": fastapi_app,
        "settings": settings,
        "upload_dir": upload_dir,
        "database": database,
    }


@pytest.fixture()
def app_env(tmp_path, monkeypatch):
    """Isolated DB + upload dir per test (OIDC configured, so the API is
    protected — clients must present a session cookie)."""
    env = make_app_env(tmp_path, monkeypatch)
    yield env
    env["database"].engine.dispose()


def make_session_token(env, roles, username="tester") -> str:
    """Mint a valid server-side session for the given roles and return its
    token (the value the session cookie must carry)."""
    from app.auth import sessions

    db = env["database"].SessionLocal()
    try:
        if "admin" in roles:
            groups = [env["settings"].admin_group]
        elif "analyst" in roles:
            groups = [env["settings"].analyst_group]
        else:
            groups = []
        session = sessions.create_session(
            db,
            sub=f"sub-{username}",
            username=username,
            email=f"{username}@packetkage.test",
            groups=groups,
            roles=list(roles),
            ttl_seconds=env["settings"].session_ttl_seconds,
        )
        return session.id
    finally:
        db.close()


@pytest.fixture(scope="session")
def oidc_provider():
    """Live fake OIDC provider on an ephemeral port (real HTTP for the token
    exchange). Only started for tests that exercise the full login flow."""
    import socket
    import threading
    import time

    import httpx
    import uvicorn
    from fake_oidc_provider import create_app

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    app = create_app(
        issuer=base,
        client_id="packetkage-test",
        client_secret="test-secret",
        redirect_uris=["http://testserver/api/auth/callback"],
    )
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(300):
        try:
            if httpx.get(f"{base}/health", timeout=0.2).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.03)
    else:
        raise RuntimeError("fake OIDC provider did not start")
    yield {"base": base, "app": app}
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture()
def app_env_with_idp(tmp_path, monkeypatch, oidc_provider):
    """App environment pointed at the live fake provider (for full flows)."""
    env = make_app_env(
        tmp_path,
        monkeypatch,
        extra_env={"PACKETKAGE_OIDC_ISSUER": oidc_provider["base"]},
    )
    yield env
    env["database"].engine.dispose()


@pytest.fixture()
def client_factory(app_env):
    """Factory returning a TestClient with a chosen role session.

    roles=None → anonymous client (no cookie); [] / ["analyst"] / ["admin"]
    → sessions with exactly those roles.
    """

    def make(roles=None, username="tester"):
        from fastapi.testclient import TestClient

        client = TestClient(app_env["app"], follow_redirects=False)
        client.__enter__()
        if roles is not None:
            token = make_session_token(app_env, roles, username)
            client.cookies.set(app_env["settings"].session_cookie, token)
        return client

    return make


@pytest.fixture()
def client(client_factory):
    """Authenticated (admin) TestClient used by the legacy product tests."""
    c = client_factory(["admin"])
    try:
        yield c
    finally:
        c.__exit__(None, None, None)
