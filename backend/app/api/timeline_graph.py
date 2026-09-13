"""Timeline + Graph endpoints (Module C/E/F)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.common import capture_or_404
from app.core.database import get_db
from app.repositories import (
    DNSRepository,
    FlowRepository,
    HostRepository,
    TimelineRepository,
    TLSRepository,
)
from app.schemas.api import GraphOut, Page, TimelineEventOut
from app.services.timeline_graph import build_graph

router = APIRouter(prefix="/api", tags=["timeline-graph"])


@router.get("/timeline", response_model=Page)
def get_timeline(
    capture_id: str,
    host: str | None = None,        # ip or domain substring
    protocol: str | None = None,
    event_type: str | None = None,
    severity: str | None = None,
    after: float | None = None,     # epoch seconds
    before: float | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """Chronological behavioral events with structured filters (Module E)."""
    capture_or_404(db, capture_id)
    events, total = TimelineRepository(db).page_for_capture(
        capture_id,
        limit=limit,
        offset=offset,
        host=host,
        protocol=protocol,
        event_type=event_type,
        severity=severity,
        after=after,
        before=before,
    )
    return Page.of(
        [TimelineEventOut.model_validate(e) for e in events],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/graph", response_model=GraphOut)
def get_graph(capture_id: str, db: Session = Depends(get_db)):
    """Cytoscape elements for the network relationship graph (Module C)."""
    capture_or_404(db, capture_id)

    flow_models = FlowRepository(db).list_for_capture(capture_id)
    dns_txns = [
        {
            "client_ip": t.client_ip, "server_ip": t.server_ip,
            "query_name": t.query_name, "response_ips": t.response_ips or [],
            "timestamp": t.timestamp,
        }
        for t in DNSRepository(db).list_for_capture(capture_id)
    ]
    tls_sessions = [
        {
            "client_ip": s.client_ip, "server_ip": s.server_ip,
            "server_port": s.server_port, "sni": s.sni, "first_seen": s.first_seen,
        }
        for s in TLSRepository(db).list_for_capture(capture_id)
    ]
    host_dicts = [
        {
            "ip": h.ip, "role": h.role, "hostname": h.hostname,
            "is_internal": bool(h.is_internal), "bytes_sent": h.bytes_sent,
            "bytes_received": h.bytes_received,
            "services": h.services or [],
            "behavior_summary": h.behavior_summary or {},
        }
        for h in HostRepository(db).list_for_capture(capture_id)
    ]

    # rebuild flow dicts for the graph builder, with REAL persisted ids
    flows = [
        {
            "id": f.id, "source_ip": f.source_ip, "destination_ip": f.destination_ip,
            "source_port": f.source_port, "destination_port": f.destination_port,
            "transport_protocol": f.transport_protocol,
            "application_protocol": f.application_protocol,
            "packets": f.packets, "bytes": f.bytes, "duration": f.duration,
            "tcp_state": f.tcp_state, "failed": bool(f.failed), "resets": f.resets,
        }
        for f in flow_models
    ]
    flow_id_map = {id(f): f["id"] for f in flows}

    return build_graph(flows, dns_txns, tls_sessions, host_dicts, flow_id_map)


@router.get("/replay", response_model=list[TimelineEventOut])
def get_replay_stream(
    capture_id: str,
    after: float | None = None,
    limit: int = Query(default=5000, ge=1, le=20000),
    db: Session = Depends(get_db),
):
    """Full chronological event stream for incident replay (Module F).

    Same data as /timeline but unfiltered, ordered, for playback.
    """
    capture_or_404(db, capture_id)
    events = TimelineRepository(db).list_for_capture(capture_id)
    if after is not None:
        # exclusive cursor (strictly later events) so paged playback never
        # re-emits the boundary event; /timeline's after is an inclusive filter
        events = [e for e in events if e.timestamp > after]
    return events[:limit]
