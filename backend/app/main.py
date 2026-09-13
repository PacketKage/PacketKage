"""PacketKage FastAPI application entry point."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import alerts, captures, cases, engineer, flows, hosts_protocols, jobs, live, timeline_graph
from app.core.config import settings
from app.core.database import Base, engine
from app.parsers import register_default_parsers


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.ensure_dirs()
    from app.db.migrate import migrate_if_sqlite

    migrate_if_sqlite()  # add columns missing in pre-existing local DBs
    Base.metadata.create_all(bind=engine)
    register_default_parsers()
    yield


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
        candidate = spa_dir / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(spa_dir / "index.html")


_mount_spa()
