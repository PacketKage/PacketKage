"""Standalone fake OIDC provider for Playwright e2e.

Reuses the exact same in-memory provider the pytest suite uses
(``backend/tests/fake_oidc_provider.py``) so the auth contract under test is
identical in unit and end-to-end runs.

Environment:
  FAKE_OIDC_PORT          listen port (default 9090)
  FAKE_OIDC_ISSUER        issuer URL advertised in discovery (default http://127.0.0.1:9090)
  FAKE_OIDC_REDIRECT_URI  the app's registered callback (default http://localhost:5173/api/auth/callback)
  FAKE_OIDC_CLIENT_ID     OAuth client id  (default packetkage-test)
  FAKE_OIDC_CLIENT_SECRET OAuth client secret (default test-secret)

Pick the identity via GET /choose?user=admin|analyst|nobody (sets a cookie);
with no cookie the provider defaults to ``admin``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import uvicorn

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "backend" / "tests"))

from fake_oidc_provider import create_app  # noqa: E402


def main() -> None:
    port = int(os.environ.get("FAKE_OIDC_PORT", "9090"))
    issuer = os.environ.get("FAKE_OIDC_ISSUER", f"http://127.0.0.1:{port}")
    redirect_uri = os.environ.get(
        "FAKE_OIDC_REDIRECT_URI", "http://localhost:5173/api/auth/callback"
    )
    app = create_app(
        issuer=issuer,
        client_id=os.environ.get("FAKE_OIDC_CLIENT_ID", "packetkage-test"),
        client_secret=os.environ.get("FAKE_OIDC_CLIENT_SECRET", "test-secret"),
        redirect_uris=[redirect_uri],
    )
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
