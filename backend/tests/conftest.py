"""Shared test fixtures: temp DB, client, generated PCAPs."""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = BACKEND_ROOT.parent / "scripts"
TESTDATA = BACKEND_ROOT.parent / "test-data" / "synthetic"


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


@pytest.fixture()
def app_env(tmp_path, monkeypatch):
    """Isolated DB + upload dir per test."""
    db_path = tmp_path / "test.db"
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    monkeypatch.setenv("PACKETKAGE_DB", f"sqlite:///{db_path}")
    monkeypatch.setenv("PACKETKAGE_UPLOAD_DIR", str(upload_dir))

    # Reimport config/engine with patched env
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]

    from app.core import config, database
    from app.main import app as fastapi_app

    importlib.reload(config)
    settings = config.Settings(
        database_url=f"sqlite:///{db_path}", upload_dir=upload_dir
    )
    config.settings = settings
    database.engine = database.make_engine(settings.database_url)
    database.SessionLocal.configure(bind=database.engine)  # type: ignore[attr-defined]
    from app.core.database import Base

    Base.metadata.create_all(bind=database.engine)
    yield {"app": fastapi_app, "settings": settings, "upload_dir": upload_dir}
    database.engine.dispose()


@pytest.fixture()
def client(app_env):
    from fastapi.testclient import TestClient

    with TestClient(app_env["app"]) as c:
        yield c
