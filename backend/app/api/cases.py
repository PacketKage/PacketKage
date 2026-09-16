"""Case endpoints — group related captures into one investigation."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.db.orm import CaptureModel, CaseModel
from app.repositories import (
    AlertRepository,
    CaptureRepository,
    CaseRepository,
    GraphEdgeRepository,
    TimelineRepository,
)
from app.schemas.api import (
    CaptureOut,
    CaseCaptureBody,
    CaseCreate,
    CaseDetailOut,
    CaseOut,
    TimelineEventOut,
)


router = APIRouter(prefix="/api/cases", tags=["cases"])


def merge_timelines(events: list) -> list:
    """Cross-capture events merged into one chronological stream."""
    return sorted(events, key=lambda e: e.timestamp)


def _case_or_404(db: Session, case_id: str):
    case = CaseRepository(db).get(case_id)
    if case is None:
        raise HTTPException(404, "Case not found")
    return case


def _case_detail(db: Session, case: CaseModel) -> CaseDetailOut:
    captures: list[CaptureModel] = []
    for cid in case.capture_ids or []:
        c = db.get(CaptureModel, cid)
        if c is not None:
            captures.append(c)

    capture_ids = [c.id for c in captures]
    # incidents belong to the capture, not per-alert
    incidents = [inc for c in captures for inc in (c.summary or {}).get("incidents", [])]
    # dedupe incidents across captures (same source + rule set)
    seen: set[tuple] = set()
    deduped: list = []
    for inc in incidents:
        key = (inc.get("source_ip"), tuple(inc.get("rule_names", [])))
        if key not in seen:
            seen.add(key)
            deduped.append(inc)

    first_ts, last_ts = TimelineRepository(db).ts_range_for_captures(capture_ids)
    stats: dict = {
        "capture_count": len(captures),
        "total_packets": sum(c.packet_count for c in captures),
        "total_alerts": 0,
        "alerts_by_severity": {},
        "incidents": sorted(deduped, key=lambda i: -i.get("max_score", 0))[:20],
        "first_event_ts": first_ts,
        "last_event_ts": last_ts,
    }
    if capture_ids:
        by_sev = AlertRepository(db).count_by_severity(capture_ids)
        stats["alerts_by_severity"] = by_sev
        stats["total_alerts"] = sum(by_sev.values())

    return CaseDetailOut(
        **CaseOut.model_validate(case).model_dump(),
        captures=[CaptureOut.model_validate(c) for c in captures],
        stats=stats,
    )


@router.get("", response_model=list[CaseOut])
def list_cases(limit: int = Query(default=100, ge=1, le=500), db: Session = Depends(get_db)):
    return CaseRepository(db).list(limit)


@router.post("", response_model=CaseDetailOut, status_code=201)
def create_case(body: CaseCreate, db: Session = Depends(get_db)):
    case = CaseRepository(db).create(name=body.name, description=body.description)
    return _case_detail(db, case)


@router.get("/{case_id}", response_model=CaseDetailOut)
def get_case(case_id: str, db: Session = Depends(get_db)):
    case = _case_or_404(db, case_id)
    return _case_detail(db, case)


@router.post("/{case_id}/captures", response_model=CaseDetailOut)
def add_capture_to_case(case_id: str, body: CaseCaptureBody, db: Session = Depends(get_db)):
    case = _case_or_404(db, case_id)
    capture = CaptureRepository(db).get(body.capture_id)
    if capture is None:
        raise HTTPException(404, "Capture not found")
    CaseRepository(db).add_capture(case, capture.id)
    # Rebuild evidence graph for this capture to add INCLUDES edge
    GraphEdgeRepository(db).rebuild_for_capture(capture.id, capture)
    return _case_detail(db, case)


@router.delete("/{case_id}/captures/{capture_id}", response_model=CaseDetailOut)
def remove_capture_from_case(case_id: str, capture_id: str, db: Session = Depends(get_db)):
    case = _case_or_404(db, case_id)
    capture = db.get(CaptureModel, capture_id)
    if capture is None:
        raise HTTPException(404, "Capture not found")
    CaseRepository(db).remove_capture(case, capture_id)
    # Rebuild evidence graph for this capture to remove INCLUDES edge
    GraphEdgeRepository(db).rebuild_for_capture(capture.id, capture)
    return _case_detail(db, case)


@router.post("/{case_id}/close", response_model=CaseOut)
def close_case(case_id: str, db: Session = Depends(get_db)):
    case = _case_or_404(db, case_id)
    return CaseRepository(db).update(case, status="closed")


@router.delete("/{case_id}", response_model=dict)
def delete_case(case_id: str, db: Session = Depends(get_db)):
    _case_or_404(db, case_id)
    CaseRepository(db).delete(case_id)
    return {"detail": "deleted"}


@router.get("/{case_id}/timeline", response_model=list[TimelineEventOut])
def case_timeline(
    case_id: str,
    event_type: str | None = None,
    severity: str | None = None,
    after: float | None = None,
    before: float | None = None,
    limit: int = Query(default=1000, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    """Merged, chronological timeline across every capture in the case."""
    case = _case_or_404(db, case_id)
    repo = TimelineRepository(db)
    events = []
    for cid in case.capture_ids or []:
        # SQL-side filtering + a per-capture cap bounds memory before the merge
        rows, _total = repo.page_for_capture(
            cid,
            limit=limit,
            event_type=event_type,
            severity=severity,
            after=after,
            before=before,
        )
        events.extend(rows)
    events = merge_timelines(events)
    return events[:limit]
