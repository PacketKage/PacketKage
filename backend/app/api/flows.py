"""Flow endpoints: paginated flow list, flow detail with packet evidence."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.common import capture_or_404
from app.core.database import get_db
from app.db.orm import CaptureModel
from app.repositories import FlowRepository, PacketRepository
from app.schemas.api import FlowDetailOut, FlowOut, PacketEvidence, Page

router = APIRouter(prefix="/api/flows", tags=["flows"])


@router.get("", response_model=Page)
def list_flows(
    capture_id: str,
    transport: str | None = None,
    direction: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    sort: str = Query(default="first_seen", pattern="^(first_seen|last_seen|packets|bytes|duration)$"),
    order: str = Query(default="asc", pattern="^(asc|desc)$"),
    db: Session = Depends(get_db),
):
    """Paginated flows for a capture (SQL-level filtering + total count)."""
    capture_or_404(db, capture_id)
    flows, total = FlowRepository(db).page_for_capture(
        capture_id,
        limit=limit,
        offset=offset,
        transport=transport,
        direction=direction,
        sort=sort,
        order=order,
    )
    return Page.of([FlowOut.model_validate(f) for f in flows], total=total, offset=offset, limit=limit)


@router.get("/{flow_id}", response_model=FlowDetailOut)
def get_flow(flow_id: str, db: Session = Depends(get_db)):
    """Flow detail including packet evidence — served from the packet store
    (no PCAP re-parsing). Falls back to empty evidence if capture was analyzed
    with an older version."""
    flow = FlowRepository(db).get(flow_id)
    if flow is None:
        raise HTTPException(404, "Flow not found")

    capture = db.get(CaptureModel, flow.capture_id)
    evidence: list[PacketEvidence] = []
    if capture is not None:
        packet_repo = PacketRepository(db)
        packets = packet_repo.get_by_refs(capture.id, list(flow.packet_refs or []))
        evidence = [
            PacketEvidence(
                timestamp=p.timestamp,
                source_ip=p.source_ip,
                destination_ip=p.destination_ip,
                protocol=p.protocol,
                transport=p.transport,
                source_port=p.source_port,
                destination_port=p.destination_port,
                length=p.length,
                flags=p.flags or [],
                metadata=p.meta or {},
                packet_reference=p.packet_reference,
            )
            for p in packets
        ]
        evidence.sort(key=lambda e: e.timestamp)

    detail = FlowDetailOut.model_validate(flow)
    detail.packet_evidence = evidence
    return detail
