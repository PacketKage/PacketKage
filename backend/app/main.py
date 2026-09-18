"""PacketKage FastAPI application entry point."""

from __future__ import annotations

import logging
import unicodedata
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.api import (
    alerts,
    captures,
    cases,
    engineer,
    evidence_graph,
    flows,
    hosts_protocols,
    jobs,
    live,
    timeline_graph,
)
from app.auth.dependencies import require_user
from app.auth.router import router as auth_router
from app.core.config import settings
from app.core.database import Base, engine
from app.parsers import register_default_parsers
from app.setup.router import router as setup_router

logger = logging.getLogger("packetkage.setup")


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.ensure_dirs()
    from app.db.migrate import migrate_if_sqlite

    migrate_if_sqlite()  # add columns missing in pre-existing local DBs
    Base.metadata.create_all(bind=engine)
    _recover_interrupted_jobs()
    register_default_parsers()
    _announce_setup_if_unconfigured()
    yield


def _announce_setup_if_unconfigured() -> None:
    """Log the first-run bootstrap token when no OIDC provider is configured.

    The setup wizard is reachable from loopback without a token; a container
    published on a non-loopback address needs the token printed here (and
    written to ``<data>/setup-token``).
    """
    if settings.auth_enabled:
        return
    from app.setup.token import bootstrap_token

    logger.warning(
        "Authentication is not configured. Open /setup and connect an OIDC provider. "
        "Bootstrap token (required for non-loopback access): %s",
        bootstrap_token(),
    )


def _recover_interrupted_jobs() -> None:
    """Mark captures/jobs orphaned by a restart as failed.

    Analysis runs in in-memory daemon threads; after a crash or restart,
    'queued'/'analyzing' captures would stay stuck forever (the atomic
    claim refuses to re-analyze them), so reconcile at startup.
    """
    from sqlalchemy import text

    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE captures SET status='failed', "
                "error='interrupted by server restart' "
                "WHERE status IN ('queued', 'analyzing')"
            )
        )
        conn.execute(
            text(
                "UPDATE analysis_jobs SET status='failed', "
                "message='interrupted by server restart' "
                "WHERE status IN ('queued', 'running')"
            )
        )


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="Network traffic analysis and investigation platform",
    lifespan=lifespan,
)

if settings.enable_cors:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


def _include_product_router(router) -> None:
    """Every PacketKage API router requires an authenticated session.

    Only the health endpoint and the OIDC front-channel (login/callback) and
    auth-router self-describing routes stay public; anything added here is
    automatically protected (enforced again by test_auth.py over OpenAPI).
    """
    app.include_router(router, dependencies=[Depends(require_user)])


_include_product_router(captures.router)
_include_product_router(jobs.router)
_include_product_router(flows.router)
_include_product_router(hosts_protocols.router)
_include_product_router(alerts.router)
_include_product_router(timeline_graph.router)
_include_product_router(evidence_graph.router)
_include_product_router(engineer.router)
_include_product_router(live.router)
_include_product_router(cases.router)
app.include_router(auth_router)
# First-run setup / reconfiguration. Mounted without the product-API auth gate:
# while unconfigured there is no session to require, so the router enforces its
# own loopback / bootstrap-token / admin guard (see app.setup.dependencies).
app.include_router(setup_router)


@app.get("/api/health")
def health():
    return {"status": "ok", "app": settings.app_name}


# ---- SPA static serving (single-container deployments) ----
# When the frontend build is present (Docker image / manual copy to backend/dist),
# serve it with a history-mode fallback so deep links (/flows?...) reach index.html.
# In local dev the folder doesn't exist and Vite serves the frontend instead.


def safe_spa_file(spa_dir: Path, full_path: str) -> Path | None:
    """Safely resolve an asset path inside spa_dir, defending against traversal."""
    if not full_path or "\0" in full_path or any(ord(c) < 32 for c in full_path):
        return None

    # Unicode normalization (NFKC) to collapse fullwidth/homoglyph dots and slashes
    normalized = unicodedata.normalize("NFKC", full_path).replace("\\", "/")
    segments = normalized.split("/")
    if any(s in ("..", ".") or not s for s in segments):
        return None
    resolved_root = spa_dir.resolve()
    try:
        candidate = (resolved_root / Path(*segments)).resolve()
        if candidate.is_file() and candidate.is_relative_to(resolved_root):
            return candidate
    except (OSError, ValueError):
        return None
    return None


def _mount_spa() -> None:
    from pathlib import Path

    from fastapi.staticfiles import StaticFiles
    from starlette.responses import FileResponse

    spa_dir = (Path(__file__).resolve().parent / "dist").resolve()
    if not (spa_dir / "index.html").exists():
        return  # frontend not built into the image — API-only mode

    app.mount("/assets", StaticFiles(directory=spa_dir / "assets"), name="spa-assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa_fallback(full_path: str):
        # Unknown /api paths must 404 like the API would, not serve the SPA.
        if full_path == "api" or full_path.startswith("api/"):
            raise HTTPException(404, "Not found")
        file_candidate = safe_spa_file(spa_dir, full_path)
        if file_candidate is not None:
            return FileResponse(file_candidate)
        return FileResponse(spa_dir / "index.html")


_mount_spa()


