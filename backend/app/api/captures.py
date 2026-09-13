"""Capture endpoints: upload, list, detail, analyze."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.parsers import ParserError, registry, resolve_parser
from app.repositories import CaptureRepository, JobRepository
from app.schemas.api import AnalyzeRequest, CaptureOut, JobOut
from app.services.jobs import job_manager

router = APIRouter(prefix="/api/captures", tags=["captures"])

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

# libpcap magic bytes: little/big-endian pcap (µs + ns variants), pcapng
PCAP_MAGIC = (
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",  # nanosecond, little-endian
    b"\xa1\xb2\x3c\x4d",  # nanosecond, big-endian
    b"\x0a\x0d\x0d\x0a",
)
CHUNK_SIZE = 1024 * 1024  # 1MB streaming chunks


def _safe_header_name(filename: str) -> str:
    """Strip everything but a conservative charset for Content-Disposition."""
    cleaned = "".join(c for c in filename if c.isalnum() or c in "._- ")
    return cleaned[:80] or "report"


@router.post("", response_model=CaptureOut, status_code=201)
async def create_capture(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Upload a PCAP/PCAPNG file and register a capture (metadata only; analysis is separate)."""
    filename = file.filename or "capture.pcap"
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"Unsupported file type {suffix!r}; allowed: {sorted(ALLOWED_EXTENSIONS)}")

    settings.ensure_dirs()
    dest = settings.upload_dir / f"{_unique_name(filename)}"
    size = 0
    first_chunk: bytes | None = None
    try:
        with dest.open("wb") as out:
            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break
                if first_chunk is None:
                    first_chunk = chunk
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    raise HTTPException(413, "File too large")
                out.write(chunk)
    except HTTPException:
        dest.unlink(missing_ok=True)  # don't leave a truncated file behind
        raise
    except OSError as exc:
        dest.unlink(missing_ok=True)
        raise HTTPException(500, f"Failed to store upload: {exc}") from exc
    except ValueError as exc:  # e.g. embedded null byte in the stored filename
        dest.unlink(missing_ok=True)
        raise HTTPException(400, f"Invalid filename: {exc}") from exc

    if size == 0 or first_chunk is None:
        dest.unlink(missing_ok=True)
        raise HTTPException(400, "Empty file")
    if len(first_chunk) < 4 or first_chunk[:4] not in PCAP_MAGIC:
        dest.unlink(missing_ok=True)
        raise HTTPException(400, "Not a valid PCAP/PCAPNG file (bad magic bytes)")

    try:
        repo = CaptureRepository(db)
        capture = repo.create(filename=filename, source="upload", size_bytes=size)
        capture = repo.update(capture, stored_path=str(dest))
    except Exception:
        dest.unlink(missing_ok=True)  # don't orphan the uploaded file on DB failure
        raise
    return capture


def _unique_name(filename: str) -> str:
    import uuid

    safe = Path(filename).name.replace("/", "_")
    return f"{uuid.uuid4().hex[:8]}_{safe}"


@router.get("", response_model=list[CaptureOut])
def list_captures(limit: int = Query(default=100, ge=1, le=500), db: Session = Depends(get_db)):
    return CaptureRepository(db).list(limit)


@router.get("/{capture_id}", response_model=CaptureOut)
def get_capture(capture_id: str, db: Session = Depends(get_db)):
    capture = CaptureRepository(db).get(capture_id)
    if capture is None:
        raise HTTPException(404, "Capture not found")
    return capture


@router.post("/{capture_id}/analyze", response_model=JobOut, status_code=202)
def analyze_capture(
    capture_id: str,
    body: AnalyzeRequest | None = None,
    db: Session = Depends(get_db),
):
    """Start background analysis for a capture. Returns the created job (poll /api/jobs/{id}).

    The status transition is an atomic guarded UPDATE — a double-click or UI
    retry cannot start a second analysis while one is queued/running.
    """
    capture_repo = CaptureRepository(db)
    capture = capture_repo.get(capture_id)
    if capture is None:
        raise HTTPException(404, "Capture not found")

    # validate requested parser up-front (fail fast, before claiming)
    requested = body.parser if body else None
    try:
        if requested not in (None, "", "auto"):
            resolve_parser(requested)
    except ParserError as exc:
        raise HTTPException(400, str(exc)) from exc

    if not capture.stored_path or not Path(capture.stored_path).exists():
        raise HTTPException(410, "Uploaded file no longer exists on disk")

    # atomic claim: exactly one concurrent caller transitions to 'queued'
    capture = capture_repo.claim_for_analysis(capture_id)
    if capture is None:
        existing = JobRepository(db).running_for_capture(capture_id)
        detail = f"Analysis already running (job {existing.id})" if existing else "Analysis already queued"
        raise HTTPException(409, detail)

    job = JobRepository(db).create(capture_id)
    try:
        job_manager.submit(capture_id, job.id, capture.stored_path, requested)
    except Exception:
        # revert the claim so the capture isn't stuck in 'queued'
        capture_repo.update(capture, status="created")
        raise
    return job


@router.get("/meta/parsers", response_model=dict[str, bool])
def list_parsers():
    """Parser availability (scapy default; tshark optional)."""
    return registry.available()


@router.get("/{capture_id}/report")
def capture_report(capture_id: str, db: Session = Depends(get_db)):
    """Download a self-contained HTML investigation report (printable to PDF)."""
    from fastapi.responses import HTMLResponse

    from app.services.report import build_report

    capture = CaptureRepository(db).get(capture_id)
    if capture is None:
        raise HTTPException(404, "Capture not found")
    if capture.status != "completed":
        raise HTTPException(409, "Capture must be analyzed before a report can be generated")

    safe_name = _safe_header_name(capture.filename)
    html_body = build_report(db, capture)
    return HTMLResponse(
        content=html_body,
        headers={
            "Content-Disposition": f'inline; filename="packetkage_report_{safe_name}.html"',
        },
    )
