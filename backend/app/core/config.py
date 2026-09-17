"""Application configuration.

OIDC client settings can come from two sources, in strict precedence order:

1. **Environment variables** — authoritative, "locked" (a declarative / CI
   deployment can never be overwritten from the UI).
2. **The persisted setup file** — written by the first-run setup wizard (or the
   admin reconfiguration form) to the data volume, so a fresh container can be
   configured without editing env/compose files.

``settings = Settings(); settings.apply_persisted()`` merges the two at import;
the setup router mutates the live ``settings`` object after a successful save,
so no process restart is needed.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BACKEND_ROOT = Path(__file__).resolve().parent.parent.parent
PROJECT_ROOT = BACKEND_ROOT.parent


def _env(name: str, default: str) -> str:
    return os.environ.get(name) or default


def _env_bool(name: str, default: bool) -> bool:
    return os.environ.get(name, "1" if default else "0").strip().lower() in ("1", "true", "yes", "on")


# ---- First-run setup persistence ------------------------------------------
# ``SETUP_FIELDS`` are the settings the wizard may persist; ``ENV_VARS`` maps
# each to the environment variable that overrides (locks) it.

SETUP_FIELDS: tuple[str, ...] = (
    "oidc_issuer",
    "oidc_client_id",
    "oidc_client_secret",
    "oidc_redirect_uri",
    "public_url",
    "oidc_scope",
    "oidc_groups_claim",
    "admin_group",
    "analyst_group",
)

ENV_VARS: dict[str, str] = {
    "oidc_issuer": "PACKETKAGE_OIDC_ISSUER",
    "oidc_client_id": "PACKETKAGE_OIDC_CLIENT_ID",
    "oidc_client_secret": "PACKETKAGE_OIDC_CLIENT_SECRET",
    "oidc_redirect_uri": "PACKETKAGE_OIDC_REDIRECT_URI",
    "public_url": "PACKETKAGE_PUBLIC_URL",
    "oidc_scope": "PACKETKAGE_OIDC_SCOPE",
    "oidc_groups_claim": "PACKETKAGE_OIDC_GROUPS_CLAIM",
    "admin_group": "PACKETKAGE_ADMIN_GROUP",
    "analyst_group": "PACKETKAGE_ANALYST_GROUP",
}

# Issuer / public URL are normalized without a trailing slash.
_URL_FIELDS = frozenset({"oidc_issuer", "public_url"})


def _clean(field_name: str, value: Any) -> str:
    text = str(value).strip()
    return text.rstrip("/") if field_name in _URL_FIELDS else text


def load_setup_file(path: Path) -> dict[str, str]:
    """Read the persisted setup values; ``{}`` when absent/corrupt/unreadable."""
    try:
        raw = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    values: dict[str, str] = {}
    for key, value in raw.items():
        if key in SETUP_FIELDS and isinstance(value, (str, int, float)):
            text = str(value).strip()
            if text:
                values[key] = text
    return values


def write_setup_file(path: Path, values: dict[str, str]) -> None:
    """Atomically persist setup values with owner-only (0600) permissions."""
    payload = {k: v for k, v in values.items() if k in SETUP_FIELDS and v}
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".setup-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


@dataclass
class Settings:
    app_name: str = "PacketKage"
    database_url: str = _env(
        "PACKETKAGE_DB",
        f"sqlite:///{BACKEND_ROOT / 'data' / 'packetkage.db'}",
    )
    upload_dir: Path = Path(
        _env(
            "PACKETKAGE_UPLOAD_DIR",
            str(BACKEND_ROOT / "data" / "uploads"),
        )
    )
    preferred_parser: str = _env("PACKETKAGE_PARSER", "auto")
    tshark_path: str = _env("PACKETKAGE_TSHARK", "tshark")
    max_upload_bytes: int = int(_env("PACKETKAGE_MAX_UPLOAD", str(500 * 1024 * 1024)))
    enable_cors: bool = _env_bool("PACKETKAGE_CORS", True)
    cors_origins: list[str] = field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"]
    )

    # ---- OpenID Connect (Authentik) authentication ------------------------
    # The identity provider is the sole source of accounts. Set PACKETKAGE_OIDC_ISSUER
    # (or complete the /setup wizard) to enable OIDC; while unset the API refuses
    # to serve (503) rather than silently running unauthenticated (fail closed).
    oidc_issuer: str = _env("PACKETKAGE_OIDC_ISSUER", "").rstrip("/")
    oidc_client_id: str = _env("PACKETKAGE_OIDC_CLIENT_ID", "")
    oidc_client_secret: str = _env("PACKETKAGE_OIDC_CLIENT_SECRET", "")
    # Canonical callback URL registered on the IdP (e.g. https://packetkage.example.com/api/auth/callback).
    # Derived from public_url + /api/auth/callback when left empty.
    oidc_redirect_uri: str = _env("PACKETKAGE_OIDC_REDIRECT_URI", "")
    oidc_scope: str = _env("PACKETKAGE_OIDC_SCOPE", "openid profile email")
    # Public base URL of this app used to build post-login redirects (ported from
    # the reverse-proxy Host header, so a hostile Host header can't steer redirects).
    public_url: str = _env("PACKETKAGE_PUBLIC_URL", "").rstrip("/")

    # Claim that carries Authentik group memberships (Authentik default: "groups").
    oidc_groups_claim: str = _env("PACKETKAGE_OIDC_GROUPS_CLAIM", "groups")
    admin_group: str = _env("PACKETKAGE_ADMIN_GROUP", "packetkage-admin")
    analyst_group: str = _env("PACKETKAGE_ANALYST_GROUP", "packetkage-analyst")

    # ---- Server-side application sessions ----------------------------------
    session_cookie: str = _env("PACKETKAGE_SESSION_COOKIE", "packetkage_session")
    session_ttl_seconds: int = int(_env("PACKETKAGE_SESSION_TTL", str(8 * 60 * 60)))
    # Set-Cookie: Secure. Defaults to on when the public URL / redirect URI is https;
    # a reverse proxy terminating TLS should leave this at its default.
    session_secure_cookie: bool | None = (
        None if not _env("PACKETKAGE_SESSION_SECURE", "") else _env_bool("PACKETKAGE_SESSION_SECURE", True)
    )

    def __post_init__(self) -> None:
        self._derive_defaults()

    # ---- Derived values ----------------------------------------------------
    def _derive_defaults(self) -> None:
        if not self.oidc_redirect_uri and self.public_url:
            self.oidc_redirect_uri = f"{self.public_url.rstrip('/')}/api/auth/callback"

    @property
    def auth_enabled(self) -> bool:
        return bool(self.oidc_issuer)

    # ---- Persisted setup file ----------------------------------------------
    @property
    def setup_file(self) -> Path:
        return Path(_env("PACKETKAGE_SETUP_FILE", str(self.upload_dir.parent / "setup.json")))

    @property
    def setup_token_file(self) -> Path:
        return self.setup_file.with_name("setup-token")

    def env_locked_fields(self) -> set[str]:
        """Setup fields whose environment variable is set (env wins, UI read-only)."""
        return {name for name, var in ENV_VARS.items() if os.environ.get(var, "").strip()}

    def apply_persisted(self) -> bool:
        """Fill unset fields from the setup file. Returns True if anything changed."""
        values = load_setup_file(self.setup_file)
        if not values:
            return False
        locked = self.env_locked_fields()
        changed = False
        for name in SETUP_FIELDS:
            if name in locked or name not in values:
                continue
            value = _clean(name, values[name])
            if value and getattr(self, name) != value:
                setattr(self, name, value)
                changed = True
        self._derive_defaults()
        return changed

    def apply_values(self, values: dict[str, str]) -> None:
        """Mutate the live settings from a (validated) field→value mapping."""
        for name, value in values.items():
            if name in SETUP_FIELDS:
                setattr(self, name, _clean(name, value))
        self._derive_defaults()

    def persist_setup(self, values: dict[str, str]) -> None:
        """Merge values into the persisted file (empty value clears the key)."""
        current = load_setup_file(self.setup_file)
        for name, value in values.items():
            if name not in SETUP_FIELDS:
                continue
            cleaned = _clean(name, value) if str(value).strip() else ""
            if cleaned:
                current[name] = cleaned
            else:
                current.pop(name, None)
        write_setup_file(self.setup_file, current)

    def ensure_dirs(self) -> None:
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        if self.database_url.startswith("sqlite:///"):
            db_path = self.database_url.replace("sqlite:///", "", 1)
            if db_path and db_path != ":memory:":
                Path(db_path).parent.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.apply_persisted()
