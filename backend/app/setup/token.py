"""One-time bootstrap token for first-run setup over a non-loopback address.

Completing OIDC configuration is a privileged action, so the setup endpoints are
open to two callers only: requests from the local machine (loopback) and
requests presenting this token. The token is read from
``PACKETKAGE_SETUP_TOKEN`` when set, otherwise generated and written to the
persisted data volume (owner-only) and logged at startup, so the operator can
retrieve it with ``docker compose logs packetkage`` or
``docker compose exec packetkage cat /data/setup-token``.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

_TOKEN_BYTES = 24
_cached: str | None = None


def _token_file() -> Path:
    from app.core import config

    return config.settings.setup_token_file


def bootstrap_token() -> str:
    global _cached
    if _cached:
        return _cached

    env = os.environ.get("PACKETKAGE_SETUP_TOKEN", "").strip()
    if env:
        _cached = env
        return _cached

    path = _token_file()
    try:
        existing = path.read_text("utf-8").strip()
    except OSError:
        existing = ""
    if existing:
        _cached = existing
        return _cached

    token = secrets.token_urlsafe(_TOKEN_BYTES)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(token + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError:
        pass  # read-only fs — the token is still available in the process/logs
    _cached = token
    return token


def token_matches(supplied: str) -> bool:
    if not supplied:
        return False
    return secrets.compare_digest(supplied, bootstrap_token())
