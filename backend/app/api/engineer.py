"""Network Engineering Mode endpoint (Module G)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.db.orm import CaptureModel
from app.repositories import DNSRepository, FlowRepository, PacketRepository
from app.services.engineer_metrics import compute_engineer_metrics

router = APIRouter(prefix="/api/engineer", tags=["engineer"])


@router.get("/metrics")
def engineer_metrics(capture_id: str, db: Session = Depends(get_db)):
    """Network health metrics computed from the packet store (no re-parsing)."""
    capture = db.get(CaptureModel, capture_id)
    if capture is None:
        raise HTTPException(404, "Capture not found")

    packet_repo = PacketRepository(db)
    count = packet_repo.count_for_capture(capture_id)
    if not count:
        raise HTTPException(410, "No stored packets for this capture — re-analyze it")
    parsed = packet_repo.as_parsed_capture(capture_id)

    # Flows + DNS from persisted tables
    flows = [
        {
            "transport_protocol": f.transport_protocol,
            "packets": f.packets,
            "retransmissions": f.retransmissions,
            "resets": f.resets,
            "failed": bool(f.failed),
            "syn_retransmissions": f.syn_retransmissions,
            "packets_reverse": f.packets_reverse,
        }
        for f in FlowRepository(db).list_for_capture(capture_id)
    ]
    dns_txns = [
        {"latency": t.latency, "rcode": t.rcode} for t in DNSRepository(db).list_for_capture(capture_id)
    ]

    metrics = compute_engineer_metrics(parsed, flows, dns_txns)
    return JSONResponse(metrics)
