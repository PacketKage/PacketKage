"""Host + protocol endpoints: hosts list/detail, DNS/HTTP/TLS transactions, protocol stats."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.common import capture_or_404
from app.core.database import get_db
from app.repositories import (
    DNSRepository,
    HostRepository,
    HTTPRepository,
    PacketRepository,
    TLSRepository,
)
from app.schemas.api import (
    DNSTransactionOut,
    HostOut,
    HTTPTransactionOut,
    Page,
    ProtocolStatsOut,
    TLSSessionOut,
)
from app.services.protocol_extractor import protocol_statistics

router = APIRouter(prefix="/api", tags=["hosts-protocols"])


# ---------------- Hosts ----------------


@router.get("/hosts", response_model=list[HostOut])
def list_hosts(
    capture_id: str,
    internal: bool | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    capture_or_404(db, capture_id)
    hosts = HostRepository(db).list_for_capture(capture_id)
    if internal is not None:
        hosts = [h for h in hosts if bool(h.is_internal) == internal]
    hosts = sorted(hosts, key=lambda h: -(h.bytes_sent + h.bytes_received))
    return hosts[:limit]


@router.get("/hosts/{host_id}", response_model=HostOut)
def get_host(host_id: str, db: Session = Depends(get_db)):
    host = HostRepository(db).get(host_id)
    if host is None:
        raise HTTPException(404, "Host not found")
    return host


# ---------------- DNS ----------------


@router.get("/protocols/dns", response_model=Page)
def list_dns(
    capture_id: str,
    domain: str | None = None,
    rcode: int | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    capture_or_404(db, capture_id)
    txns, total = DNSRepository(db).page_for_capture(
        capture_id, limit=limit, offset=offset, domain=domain, rcode=rcode
    )
    return Page.of(
        [DNSTransactionOut.model_validate(t) for t in txns],
        total=total,
        offset=offset,
        limit=limit,
    )


# ---------------- HTTP ----------------


@router.get("/protocols/http", response_model=Page)
def list_http(
    capture_id: str,
    host: str | None = None,
    status: int | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    capture_or_404(db, capture_id)
    txns, total = HTTPRepository(db).page_for_capture(
        capture_id, limit=limit, offset=offset, host=host, status=status
    )
    return Page.of(
        [HTTPTransactionOut.model_validate(t) for t in txns],
        total=total,
        offset=offset,
        limit=limit,
    )


# ---------------- TLS ----------------


@router.get("/protocols/tls", response_model=Page)
def list_tls(
    capture_id: str,
    sni: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    capture_or_404(db, capture_id)
    sessions, total = TLSRepository(db).page_for_capture(capture_id, limit=limit, offset=offset, sni=sni)
    return Page.of(
        [TLSSessionOut.model_validate(s) for s in sessions],
        total=total,
        offset=offset,
        limit=limit,
    )


# ---------------- Protocol stats (Module J) ----------------


@router.get("/protocols/stats", response_model=ProtocolStatsOut)
def protocol_stats(capture_id: str, db: Session = Depends(get_db)):
    """Protocol stats served from the packet store (no PCAP re-parsing)."""
    capture_or_404(db, capture_id)
    parsed = PacketRepository(db).as_parsed_capture(capture_id)
    return protocol_statistics(parsed)
