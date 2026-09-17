#!/usr/bin/env python3
"""One-shot local dev bootstrap for PacketKage + bundled Authentik.

Automates the boring, error-prone parts of the "Option A — bundled Authentik"
walkthrough:

1. writes `.env` (copy from `.env.example`) and fills the three required
   Authentik secrets with strong random values;
2. starts only the Authentik services (postgresql/redis/server/worker) so it
   never collides with a native `uvicorn` on :8000;
3. waits until Authentik is healthy;
4. creates the two groups, the OAuth2/OpenID provider, and the application via
   Authentik's REST API (using the bootstrap token), then reads back the
   client id/secret;
5. writes `backend/data/setup.json` so PacketKage starts *already configured*
   (no wizard typing), and prints what to run next.

Because `.env` is read by podman-compose/docker-compose but NOT by the native
backend, PacketKage is configured through the persisted setup file instead. Any
`PACKETKAGE_OIDC_*` you export in your shell still wins over it.

Usage
-----
    python3 scripts/packetkage-setup.py                 # full auto
    python3 scripts/packetkage-setup.py --public-url http://localhost:8000
    python3 scripts/packetkage-setup.py --manual        # pause for UI-created client id/secret
    python3 scripts/packetkage-setup.py --dry-run       # show what it would do
    python3 scripts/packetkage-setup.py --no-start      # configure only, don't start containers

Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import getpass
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = REPO_ROOT / ".env"
ENV_EXAMPLE = REPO_ROOT / ".env.example"

AUTHENTIK_SERVICES = ["postgresql", "redis", "authentik-server", "authentik-worker"]
PLACEHOLDER_PREFIX = "replace-with"

ENV_SECRETS = {
    "AUTHENTIK_SECRET_KEY": 36,
    "AUTHENTIK_POSTGRESQL__PASSWORD": 24,
    "AUTHENTIK_BOOTSTRAP_TOKEN": 32,
}

GROUP_ADMIN = "packetkage-admin"
GROUP_ANALYST = "packetkage-analyst"
PROVIDER_NAME = "packetkage"
APP_NAME = "PacketKage"
APP_SLUG = "packetkage"
AUTH_FLOW_SLUG = "default-provider-authorization-implicit-consent"
INVALIDATION_FLOW_SLUG = "default-provider-invalidation-flow"


# --------------------------------------------------------------------------- #
# tiny logging helpers
# --------------------------------------------------------------------------- #
def say(message: str = "") -> None:
    print(message, flush=True)


def step(message: str) -> None:
    say(f"\n\033[1m==> {message}\033[0m")


def warn(message: str) -> None:
    say(f"  ! {message}")


def ok(message: str) -> None:
    say(f"  ✓ {message}")


def fail(message: str) -> None:
    say(f"\n\033[31mError:\033[0m {message}")
    sys.exit(1)


# --------------------------------------------------------------------------- #
# .env handling
# --------------------------------------------------------------------------- #
def random_secret(num_bytes: int) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(num_bytes)).decode().rstrip("=")


def is_placeholder(value: str | None) -> bool:
    return not value or value.strip().startswith(PLACEHOLDER_PREFIX)


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def set_env_values(path: Path, updates: dict[str, str]) -> None:
    """Replace `KEY=...` lines in place, appending any missing keys."""
    lines = path.read_text("utf-8").splitlines() if path.exists() else []
    remaining = dict(updates)
    out: list[str] = []
    for line in lines:
        match = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if match and match.group(1) in remaining:
            key = match.group(1)
            out.append(f"{key}={remaining.pop(key)}")
        else:
            out.append(line)
    if remaining:
        if out and out[-1].strip():
            out.append("")
        out.append("# --- added by scripts/packetkage-setup.py ---")
        for key, value in remaining.items():
            out.append(f"{key}={value}")
    path.write_text("\n".join(out) + "\n", "utf-8")
    with contextlib.suppress(OSError):
        path.chmod(0o600)


def prepare_env(args: argparse.Namespace) -> dict[str, str]:
    step("Preparing .env")
    if not ENV_FILE.exists():
        if not ENV_EXAMPLE.exists():
            fail(f"{ENV_EXAMPLE} not found; run from the repository.")
        if args.dry_run:
            say(f"  would copy {ENV_EXAMPLE.name} -> {ENV_FILE.name}")
        else:
            shutil.copyfile(ENV_EXAMPLE, ENV_FILE)
            ok(f"created {ENV_FILE.relative_to(REPO_ROOT)}")
    else:
        say(f"  using existing {ENV_FILE.relative_to(REPO_ROOT)}")

    current = read_env(ENV_FILE)
    updates: dict[str, str] = {}

    for key, size in ENV_SECRETS.items():
        if is_placeholder(current.get(key)):
            updates[key] = random_secret(size)
            ok(f"generated {key}")

    if is_placeholder(current.get("AUTHENTIK_BOOTSTRAP_PASSWORD")):
        if args.yes or not sys.stdin.isatty():
            password = random_secret(18)
        else:
            password = getpass.getpass(
                "  Choose an akadmin password (blank = generate one): "
            ).strip() or random_secret(18)
        updates["AUTHENTIK_BOOTSTRAP_PASSWORD"] = password
        ok("set AUTHENTIK_BOOTSTRAP_PASSWORD")

    if args.dry_run:
        for key in updates:
            say(f"  would set {key}")
        merged = {**current, **updates}
    else:
        if updates:
            set_env_values(ENV_FILE, updates)
        merged = read_env(ENV_FILE)

    # remember generated values for the summary even on a dry run
    for key, value in updates.items():
        merged.setdefault(key, value)
    return merged


# --------------------------------------------------------------------------- #
# compose
# --------------------------------------------------------------------------- #
def compose_command() -> list[str]:
    if shutil.which("podman-compose"):
        return ["podman-compose"]
    if shutil.which("docker"):
        try:
            subprocess.run(
                ["docker", "compose", "version"],
                check=True,
                capture_output=True,
                text=True,
            )
            return ["docker", "compose"]
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
    fail("neither podman-compose nor the docker compose plugin is available.")


def compose_files() -> list[str]:
    return [
        "-f",
        str(REPO_ROOT / "docker-compose.yml"),
        "-f",
        str(REPO_ROOT / "docker-compose.authentik.yml"),
    ]


def start_authentik(args: argparse.Namespace, compose: list[str]) -> None:
    step("Starting Authentik containers")
    cmd = compose + compose_files() + ["up", "-d", *AUTHENTIK_SERVICES]
    say("  " + " ".join(cmd))
    if args.dry_run:
        return
    result = subprocess.run(cmd, cwd=REPO_ROOT, check=False)
    if result.returncode != 0:
        fail("compose failed to start Authentik (see output above).")
    ok("containers launched")


def http_json(
    url: str,
    method: str = "GET",
    payload: dict | None = None,
    token: str | None = None,
    timeout: float = 15.0,
) -> tuple[int, object]:
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
            try:
                return response.status, (json.loads(body) if body else None)
            except ValueError:
                return response.status, body.decode(errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            detail = json.loads(body)
        except ValueError:
            detail = body.decode(errors="replace")
        return exc.code, detail
    except (urllib.error.URLError, OSError) as exc:
        # ConnectionResetError / ConnectionRefusedError / timeouts are OSError,
        # not URLError, and happen routinely while a container is still booting.
        reason = getattr(exc, "reason", exc)
        return 0, str(reason)


def wait_for_authentik(
    authentik_url: str, token: str, args: argparse.Namespace
) -> None:
    step("Waiting for Authentik to become ready")
    if args.dry_run:
        say("  would poll /-/health/ready/")
        return
    deadline = time.time() + 420
    health_url = f"{authentik_url}/-/health/ready/"
    while time.time() < deadline:
        status, _ = http_json(health_url, timeout=5)
        if status == 200:
            break
        say("  … still starting (DB migrations can take a minute)")
        time.sleep(5)
    else:
        fail(
            "Authentik did not become ready in 7 minutes. Inspect the logs:\n"
            f"  {' '.join(compose_command() + compose_files() + ['logs', '-f', 'authentik-server'])}"
        )
    ok("Authentik is healthy")

    if not token:
        return
    api = f"{authentik_url}/api/v3/core/users/me/"
    deadline = time.time() + 120
    while time.time() < deadline:
        status, _ = http_json(api, token=token)
        if status == 200:
            ok("bootstrap API token is valid")
            return
        time.sleep(3)
    warn("bootstrap token not accepted yet; API provisioning may fail.")


# --------------------------------------------------------------------------- #
# Authentik API provisioning
# --------------------------------------------------------------------------- #
class Authentik:
    def __init__(self, base: str, token: str):
        self.base = base.rstrip("/")
        self.token = token

    def call(self, method: str, path: str, payload: dict | None = None):
        status, body = http_json(f"{self.base}{path}", method, payload, self.token)
        if status == 0:
            fail(f"cannot reach Authentik API ({body})")
        if status >= 400:
            detail = body
            if isinstance(body, dict):
                detail = body.get("detail") or body
            fail(f"{method} {path} -> HTTP {status}: {detail}")
        return body

    def first(self, path: str):
        body = self.call("GET", path)
        results = body.get("results", []) if isinstance(body, dict) else []
        return results[0] if results else None

    def ensure_group(self, name: str) -> str:
        existing = self.first(f"/api/v3/core/groups/?name={urllib.parse.quote(name)}")
        if existing:
            return existing["pk"]
        created = self.call("POST", "/api/v3/core/groups/", {"name": name})
        return created["pk"]

    def admin_user_pk(self) -> int:
        me = self.call("GET", "/api/v3/core/users/me/")
        user = me.get("user", me)
        return user["pk"]

    def add_user(self, group_pk: str, user_pk: int) -> None:
        status, _ = http_json(
            f"{self.base}/api/v3/core/groups/{group_pk}/add_user/",
            "POST",
            {"pk": user_pk},
            self.token,
        )
        if status >= 400:
            warn(f"could not add user {user_pk} to group {group_pk} (HTTP {status})")

    def authorization_flow(self) -> str:
        flow = self.first(f"/api/v3/flows/instances/?slug={AUTH_FLOW_SLUG}")
        if not flow:
            flow = self.first("/api/v3/flows/instances/?designation=authorization")
        if not flow:
            fail("no authorization flow found in Authentik.")
        return flow["pk"]

    def invalidation_flow(self) -> str:
        flow = self.first(f"/api/v3/flows/instances/?slug={INVALIDATION_FLOW_SLUG}")
        if not flow:
            flow = self.first("/api/v3/flows/instances/?designation=invalidation")
        if not flow:
            fail("no invalidation flow found in Authentik.")
        return flow["pk"]

    def signing_key(self) -> str | None:
        cert = self.first("/api/v3/crypto/certificatekeypairs/?has_key=true")
        return cert["pk"] if cert else None

    def scope_mappings(self) -> list[str]:
        body = self.call("GET", "/api/v3/propertymappings/all/?page_size=1000")
        wanted = {"openid", "profile", "email"}
        pks: list[str] = []
        for mapping in body.get("results", []):
            match = re.search(r"OpenID '([^']+)'", mapping.get("name", ""))
            if match and match.group(1).lower() in wanted:
                pks.append(mapping["pk"])
        if not pks:
            warn("no default scope mappings found; tokens may lack the groups claim.")
        return pks

    def ensure_provider(self, redirect_uri: str) -> dict:
        existing = self.first(
            f"/api/v3/providers/oauth2/?name={urllib.parse.quote(PROVIDER_NAME)}"
        )
        desired_redirect = [{"matching_mode": "strict", "url": redirect_uri}]
        if existing:
            current = {
                (entry or {}).get("url")
                for entry in (existing.get("redirect_uris") or [])
            }
            if redirect_uri not in current:
                merged = list(existing.get("redirect_uris") or []) + desired_redirect
                self.call(
                    "PATCH",
                    f"/api/v3/providers/oauth2/{existing['pk']}/",
                    {"redirect_uris": merged},
                )
                ok(f"added redirect URI to existing provider '{PROVIDER_NAME}'")
            else:
                say(f"  provider '{PROVIDER_NAME}' already exists")
            return existing

        payload = {
            "name": PROVIDER_NAME,
            "authorization_flow": self.authorization_flow(),
            "invalidation_flow": self.invalidation_flow(),
            "client_type": "confidential",
            "redirect_uris": desired_redirect,
            "sub_mode": "user_username",
            "property_mappings": self.scope_mappings(),
        }
        signing_key = self.signing_key()
        if signing_key:
            payload["signing_key"] = signing_key
        return self.call("POST", "/api/v3/providers/oauth2/", payload)

    def ensure_application(self, provider_pk) -> None:
        existing = self.first(
            f"/api/v3/core/applications/?slug={urllib.parse.quote(APP_SLUG)}"
        )
        if existing:
            say(f"  application '{APP_SLUG}' already exists")
            return
        self.call(
            "POST",
            "/api/v3/core/applications/",
            {"name": APP_NAME, "slug": APP_SLUG, "provider": provider_pk},
        )

    def provision(self, redirect_uri: str) -> dict:
        step("Provisioning groups, provider and application via the Authentik API")
        admin_group = self.ensure_group(GROUP_ADMIN)
        analyst_group = self.ensure_group(GROUP_ANALYST)
        ok(f"groups ready ({GROUP_ADMIN}, {GROUP_ANALYST})")

        provider = self.ensure_provider(redirect_uri)
        self.ensure_application(provider["pk"])
        ok(f"provider ready (client_id={provider['client_id']})")

        self.add_user(admin_group, self.admin_user_pk())
        self.add_user(analyst_group, self.admin_user_pk())
        ok("akadmin added to both groups")

        return {
            "client_id": provider["client_id"],
            "client_secret": provider["client_secret"],
        }


def manual_credentials() -> dict:
    step("Manual provider setup")
    say("  In Authentik (http://localhost:9000) create the OAuth2/OpenID provider")
    say("  with redirect URI below, then paste the credentials here.")
    client_id = input("  Client ID: ").strip()
    client_secret = getpass.getpass("  Client secret: ").strip()
    if not client_id or not client_secret:
        fail("client id and secret are required.")
    return {"client_id": client_id, "client_secret": client_secret}


# --------------------------------------------------------------------------- #
# PacketKage config
# --------------------------------------------------------------------------- #
def setup_file_path() -> Path:
    override = os.environ.get("PACKETKAGE_SETUP_FILE", "").strip()
    if override:
        return Path(override)
    upload_dir = os.environ.get("PACKETKAGE_UPLOAD_DIR", "").strip()
    if upload_dir:
        return Path(upload_dir).parent / "setup.json"
    return REPO_ROOT / "backend" / "data" / "setup.json"


def write_packetkage_config(values: dict[str, str], args: argparse.Namespace) -> Path:
    path = setup_file_path()
    step("Writing PacketKage configuration")
    say(f"  {path}")
    if args.dry_run:
        for key, value in values.items():
            shown = "********" if key == "oidc_client_secret" else value
            say(f"    {key} = {shown}")
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(values, indent=2, sort_keys=True) + "\n", "utf-8")
    with contextlib.suppress(OSError):
        path.chmod(0o600)
    ok("saved (owner-only). PacketKage will start already configured.")
    return path


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bootstrap PacketKage + bundled Authentik for local development."
    )
    parser.add_argument(
        "--public-url",
        default="http://localhost:5173",
        help="Browser-facing PacketKage URL (default: Vite dev server).",
    )
    parser.add_argument(
        "--authentik-url",
        default="http://localhost:9000",
        help="Authentik base URL as reachable from this host.",
    )
    parser.add_argument(
        "--issuer",
        default=None,
        help="OIDC issuer (default: <authentik-url>/application/o/packetkage/).",
    )
    parser.add_argument(
        "--no-start",
        action="store_true",
        help="Do not start containers (assume Authentik already running).",
    )
    parser.add_argument(
        "--manual",
        action="store_true",
        help="Skip API provisioning and prompt for a UI-created client id/secret.",
    )
    parser.add_argument(
        "--no-config",
        action="store_true",
        help="Do not write setup.json (only .env + Authentik).",
    )
    parser.add_argument(
        "--print-only",
        action="store_true",
        help="Print the resulting configuration instead of writing setup.json.",
    )
    parser.add_argument("--yes", action="store_true", help="Non-interactive defaults.")
    parser.add_argument("--dry-run", action="store_true", help="Show actions only.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    public_url = args.public_url.rstrip("/")
    authentik_url = args.authentik_url.rstrip("/")
    issuer = (args.issuer or f"{authentik_url}/application/o/{APP_SLUG}/").rstrip("/")
    redirect_uri = f"{public_url}/api/auth/callback"

    say("PacketKage + Authentik dev bootstrap")
    say(f"  repo:        {REPO_ROOT}")
    say(f"  public URL:  {public_url}")
    say(f"  issuer:      {issuer}")

    env = prepare_env(args)
    compose = compose_command()

    if not args.no_start:
        start_authentik(args, compose)
        wait_for_authentik(
            authentik_url, env.get("AUTHENTIK_BOOTSTRAP_TOKEN", ""), args
        )
    else:
        step("Skipping container start (--no-start)")

    if args.manual:
        credentials = manual_credentials()
    else:
        token = env.get("AUTHENTIK_BOOTSTRAP_TOKEN", "")
        if args.dry_run:
            step("Would provision via the Authentik API")
            credentials = {"client_id": "<generated>", "client_secret": "<generated>"}
        elif not token:
            fail("no AUTHENTIK_BOOTSTRAP_TOKEN in .env; re-run or use --manual.")
        else:
            credentials = Authentik(authentik_url, token).provision(redirect_uri)

    config = {
        "oidc_issuer": issuer,
        "oidc_client_id": credentials["client_id"],
        "oidc_client_secret": credentials["client_secret"],
        "oidc_redirect_uri": redirect_uri,
        "public_url": public_url,
        "admin_group": GROUP_ADMIN,
        "analyst_group": GROUP_ANALYST,
    }

    if args.print_only:
        step("Configuration (not written)")
        for key, value in config.items():
            shown = "********" if key == "oidc_client_secret" else value
            say(f"  {key} = {shown}")
        config_path = None
    elif not args.no_config:
        config_path = write_packetkage_config(config, args)
    else:
        config_path = None

    step("Done")
    if config_path and not args.dry_run:
        say(f"  config saved to {config_path}")
    say("  Authentik admin:  http://localhost:9000  (user: akadmin)")
    say("")
    say("  Next, in two terminals:")
    say("    1) cd backend && source .venv/bin/activate \\")
    say("         && python -m uvicorn app.main:app --reload --port 8000")
    say("    2) cd frontend && npm run dev")
    say(f"    open {public_url} and sign in as akadmin")
    if not args.dry_run:
        say("")
        say(
            "  If the backend was already running, restart it so it reloads the config."
        )


if __name__ == "__main__":
    main()
