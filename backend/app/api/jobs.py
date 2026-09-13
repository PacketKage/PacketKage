"""Jobs endpoints: status polling + SSE progress stream."""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.db.orm import AnalysisJobModel
from app.repositories import JobRepository
from app.schemas.api import JobOut

router = APIRouter(prefix="/api/jobs", tags=["jobs"])

TERMINAL = {"completed", "failed"}


@router.get("", response_model=list[JobOut])
def list_jobs(limit: int = Query(default=50, ge=1, le=500), db: Session = Depends(get_db)):
    stmt = select(AnalysisJobModel).order_by(desc(AnalysisJobModel.created_at)).limit(limit)
    return list(db.scalars(stmt))


@router.get("/{job_id}", response_model=JobOut)
def get_job(job_id: str, db: Session = Depends(get_db)):
    job = JobRepository(db).get(job_id)
    if job is None:
        raise HTTPException(404, "Job not found")
    return job


@router.get("/{job_id}/events")
async def job_events(
    job_id: str, poll_interval: float = Query(default=0.5, ge=0.1, le=30)
):
    """SSE stream of job progress until terminal state.

    Each event is a JSON JobOut snapshot; stream closes after the terminal
    snapshot is sent, so the client just needs one EventSource connection.
    """
    from app.core.database import SessionLocal

    async def stream():
        try:
            while True:
                # fresh short-lived session per poll; jobs run in other threads
                db: Session = SessionLocal()
                try:
                    job = db.get(AnalysisJobModel, job_id)
                    if job is None:
                        yield f"event: error\ndata: {job_id} not found\n\n"
                        return
                    snapshot = JobOut.model_validate(job).model_dump(mode="json")
                    # MUST be json.dumps — an f-string would emit Python dict
                    # repr (single quotes), which JSON.parse rejects in the
                    # browser, killing every SSE handler (regression-tested
                    # in test_step1.py::test_job_events_stream_is_valid_json).
                    yield f"data: {json.dumps(snapshot)}\n\n"
                    if job.status in TERMINAL:
                        return
                finally:
                    db.close()
                await asyncio.sleep(poll_interval)
        finally:
            pass  # client disconnected; nothing to clean up

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
