"""Background job manager — runs analysis jobs off the request thread.

SQLite note: each job runs in its own thread with its own session to avoid
cross-thread session sharing. WAL-friendly and simple for v1.
"""

from __future__ import annotations

import threading

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.services.analysis import AnalysisService


class JobManager:
    def __init__(self) -> None:
        self._threads: dict[str, threading.Thread] = {}
        self._lock = threading.Lock()

    def submit(self, capture_id: str, job_id: str, file_path: str | None, parser_name: str | None) -> None:
        thread = threading.Thread(
            target=self._run_job,
            args=(capture_id, job_id, file_path, parser_name),
            daemon=True,
            name=f"analysis-{job_id[:8]}",
        )
        with self._lock:
            self._threads[job_id] = thread
        thread.start()

    def _run_job(self, capture_id: str, job_id: str, file_path: str, parser_name: str | None) -> None:
        db: Session = SessionLocal()
        try:
            service = AnalysisService(db)
            capture = service.captures.get(capture_id)
            job = service.jobs.get(job_id)
            if capture is None or job is None:
                return
            service.run_full_analysis(capture, job, parser_name=parser_name, file_path=file_path)
        finally:
            db.close()
            with self._lock:
                self._threads.pop(job_id, None)


job_manager = JobManager()
