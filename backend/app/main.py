"""PacketKage FastAPI application entry point."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
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
from app.core.config import settings
from app.core.database import Base, engine
from app.parsers import register_default_parsers


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.ensure_dirs()
    from app.db.migrate import migrate_if_sqlite

    migrate_if_sqlite()  # add columns missing in pre-existing local DBs
    Base.metadata.create_all(bind=engine)
    _recover_interrupted_jobs()
    register_default_parsers()
    yield


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

app.include_router(captures.router)
app.include_router(jobs.router)
app.include_router(flows.router)
app.include_router(hosts_protocols.router)
app.include_router(alerts.router)
app.include_router(timeline_graph.router)
app.include_router(evidence_graph.router)
app.include_router(engineer.router)
app.include_router(live.router)
app.include_router(cases.router)


@app.get("/api/health")
def health():
    return {"status": "ok", "app": settings.app_name}


# ---- SPA static serving (single-container deployments) ----
# When the frontend build is present (Docker image / manual copy to backend/dist),
# serve it with a history-mode fallback so deep links (/flows?...) reach index.html.
# In local dev the folder doesn't exist and Vite serves the frontend instead.


def _mount_spa() -> None:
    from pathlib import Path

    from fastapi.staticfiles import StaticFiles
    from starlette.responses import FileResponse

    spa_dir = Path(__file__).resolve().parent / "dist"
    if not (spa_dir / "index.html").exists():
        return  # frontend not built into the image — API-only mode

    app.mount("/assets", StaticFiles(directory=spa_dir / "assets"), name="spa-assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa_fallback(full_path: str):
        # Unknown /api paths must 404 like the API would, not serve the SPA.
        if full_path == "api" or full_path.startswith("api/"):
            raise HTTPException(404, "Not found")
        try:
            candidate = (spa_dir / full_path).resolve()
        except OSError:
            candidate = None
        if candidate is not None and full_path and candidate.is_file() and candidate.is_relative_to(
            spa_dir.resolve()
        ):
            # Starlette's :path converter passes percent-decoded input —
            # bound-check against spa_dir or /../ traversal reads arbitrary files.
            return FileResponse(candidate)
        return FileResponse(spa_dir / "index.html")


_mount_spa()
