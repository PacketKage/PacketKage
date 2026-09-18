"""Tests for SPA fallback and path traversal protections in static serving."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app, safe_spa_file


def test_api_unknown_route_returns_404():
    client = TestClient(app)
    # Unknown API path should return 404 JSON, not SPA index.html
    resp = client.get("/api/unknown-endpoint-xyz")
    assert resp.status_code == 404


def test_safe_spa_file_valid(tmp_path: Path):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html></html>")
    assets = dist / "assets"
    assets.mkdir()
    app_js = assets / "app.js"
    app_js.write_text("console.log(1);")

    # Valid relative assets inside dist
    assert safe_spa_file(dist, "assets/app.js") == app_js.resolve()
    assert safe_spa_file(dist, "index.html") == (dist / "index.html").resolve()


def test_safe_spa_file_traversal_attempts(tmp_path: Path):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html></html>")
    secret = tmp_path / "secret.txt"
    secret.write_text("SUPER_SECRET_TOKEN")

    # Traversal payloads must all return None
    assert safe_spa_file(dist, "../secret.txt") is None
    assert safe_spa_file(dist, "assets/../../secret.txt") is None
    assert safe_spa_file(dist, r"..\secret.txt") is None
    assert safe_spa_file(dist, "\uff0e\uff0e/secret.txt") is None
    assert safe_spa_file(dist, "\uff0e\uff0e/\uff0e\uff0e/secret.txt") is None
    assert safe_spa_file(dist, "/etc/passwd") is None
    assert safe_spa_file(dist, "assets/app.js\0.html") is None
    assert safe_spa_file(dist, "assets//app.js") is None
    assert safe_spa_file(dist, "") is None

