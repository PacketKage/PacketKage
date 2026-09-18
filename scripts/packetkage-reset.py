#!/usr/bin/env python3
"""Wipe every locally-generated dev artifact so the next clone feels fresh.

Companion to `packetkage-setup.py`. It removes ONLY what that script (or a
previous dev session) created — never repo source, never the old `packetkage_*`
stack from another directory, never `*.example` templates:

1. `.env` (the random secrets generated at the repo root);
2. backend `data/` (setup.json, setup-token, uploads, the sqlite DB);
3. the generated test PCAPs under `test-data/synthetic/`;
4. this repo's compose project (`packetkagetest_*`) — every container and every
   named volume (postgres/redis/media/templates/certs).

After it runs, re-run `python3 scripts/packetkage-setup.py` to rebuild
everything from scratch. The teardown targets only containers/volumes whose
name starts with `packetkagetest` (the project name derived from this
directory), so it cannot touch the `/projects/PacketKage` stack or any other
compose project.

Usage
-----
    python3 scripts/packetkage-reset.py            # remove everything
    python3 scripts/packetkage-reset.py --dry-run # just list what it would do
    python3 scripts/packetkage-reset.py --keep-pcaps   # keep generated test data

Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = REPO_ROOT / ".env"
ENV_EXAMPLE = REPO_ROOT / ".env.example"
BACKEND_DATA = REPO_ROOT / "backend" / "data"
TEST_DATA = REPO_ROOT / "test-data" / "synthetic"

# Compose derives the project name from the directory basename.
PROJECT = REPO_ROOT.name  # e.g. "PacketKageTest" → "packetkagetest"


# --------------------------------------------------------------------------- #
# tiny logging helpers (same style as packetkage-setup.py)
# --------------------------------------------------------------------------- #
def say(message: str = "") -> None:
    print(message, flush=True)


def step(message: str) -> None:
    say(f"\n\033[1m==> {message}\033[0m")


def ok(message: str) -> None:
    say(f"  ✓ {message}")


def warn(message: str) -> None:
    say(f"  ! {message}")


def fail(message: str) -> None:
    say(f"\n\033[31mError:\033[0m {message}")
    sys.exit(1)


# --------------------------------------------------------------------------- #
# compose / container tooling
# --------------------------------------------------------------------------- #
def compose_command() -> list[str] | None:
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
    return None  # compose absent → skip container teardown, still clean files


def container_binary() -> str | None:
    if shutil.which("podman"):
        return "podman"
    if shutil.which("docker"):
        return "docker"
    return None


def project_prefix() -> str:
    """Containers/volumes use lowercase project prefix `packetkagetest_`."""
    return f"{PROJECT.lower()}_"


def remove_project_artifacts(args: argparse.Namespace) -> None:
    step("Removing containers and volumes")
    prefix = project_prefix()

    compose = compose_command()
    if compose is not None:
        cmd = compose + ["-f", str(REPO_ROOT / "docker-compose.yml"), "-f",
                         str(REPO_ROOT / "docker-compose.authentik.yml"),
                         "down"] + (["-v", "--remove-orphans"] if not args.dry_run else [])
        say("  " + " ".join(cmd))
        if not args.dry_run:
            result = subprocess.run(cmd, cwd=REPO_ROOT, check=False)
            if result.returncode != 0:
                warn("compose down reported errors; falling back to manual cleanup")

    binary = container_binary()
    if binary is None:
        if not args.dry_run:
            warn("no podman/docker found — could not verify leftover containers")
        return
    if args.dry_run:
        say(f"  would remove all `{binary}` containers/volumes named {prefix}*")
        return

    def _list(kind: str) -> list[str]:
        try:
            out = subprocess.run(
                [binary, kind, "ls", "--format", "{{.Names}}"],
                capture_output=True, text=True, check=False,
            ).stdout
        except OSError:
            return []
        return [line.strip() for line in out.splitlines() if line.strip().startswith(prefix)]

    removed = False
    for kind in ("container", "volume"):
        for name in _list(kind):
            try:
                subprocess.run([binary, kind, "rm", "-f", name], check=False, capture_output=True)
            except OSError:
                continue
            ok(f"removed {name}")
            removed = True
    if not removed:
        ok(f"no {binary} {prefix}* containers/volumes present")


# --------------------------------------------------------------------------- #
# file cleanup
# --------------------------------------------------------------------------- #
def remove_env(args: argparse.Namespace) -> None:
    step("Removing .env")
    if not ENV_FILE.exists():
        ok(".env not present (already clean)")
        return
    if args.dry_run:
        say(f"  would remove {ENV_FILE.relative_to(REPO_ROOT)}")
        return
    ENV_FILE.unlink()
    ok(f"removed {ENV_FILE.relative_to(REPO_ROOT)} (template {ENV_EXAMPLE.relative_to(REPO_ROOT)} kept)")


def remove_backend_data(args: argparse.Namespace) -> None:
    step("Removing backend data")
    if not BACKEND_DATA.exists():
        ok("backend/data not present (already clean)")
        return
    if args.dry_run:
        say(f"  would delete {BACKEND_DATA.relative_to(REPO_ROOT)}/ (setup.json, uploads, sqlite)")
        return
    shutil.rmtree(BACKEND_DATA)
    ok(f"removed backend/data/ (setup.json, uploads, sqlite)")


def remove_test_pcaps(args: argparse.Namespace) -> None:
    if args.keep_pcaps:
        step("Keeping generated test PCAPs (--keep-pcaps)")
        return
    step("Removing generated test PCAPs")
    if not TEST_DATA.exists() or not any(TEST_DATA.iterdir()):
        ok("test-data/synthetic has no generated PCAPs (already clean)")
        return
    removed = [p.name for p in TEST_DATA.iterdir() if p.suffix.lower() in (".pcap", ".pcapng")]
    if not removed:
        ok("no *.pcap files under test-data/synthetic")
        return
    if args.dry_run:
        say("  would remove " + ", ".join(removed))
        return
    for p in TEST_DATA.iterdir():
        if p.suffix.lower() in (".pcap", ".pcapng"):
            p.unlink()
    try:
        TEST_DATA.rmdir()
    except OSError:
        pass
    ok(f"removed {len(removed)} generated PCAP(s)")


# --------------------------------------------------------------------------- #
# entrypoint
# --------------------------------------------------------------------------- #
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="packetkage-reset.py",
        description="Wipe PacketKage dev artifacts (env, backend data, test PCAPs, "
                    "Authentik containers/volumes) so a setup re-run starts fresh.",
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="print what would be removed without changing anything")
    parser.add_argument("--keep-pcaps", action="store_true",
                        help="keep generated test-data/synthetic PCAPs")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    say(
        f"PacketKage dev reset for project `{PROJECT.lower()}`\n"
        f"  repo: {REPO_ROOT}"
    )
    if args.dry_run:
        warn("dry run — nothing will be changed")

    remove_project_artifacts(args)
    remove_env(args)
    remove_backend_data(args)
    remove_test_pcaps(args)

    step("Done")
    if args.dry_run:
        say("  dry run finished — re-run without --dry-run to actually remove")
    else:
        say("  re-run python3 scripts/packetkage-setup.py to rebuild fresh")


if __name__ == "__main__":
    main()