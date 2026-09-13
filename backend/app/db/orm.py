"""SQLAlchemy ORM models (SQLite persistence layer)."""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class CaptureModel(Base):
    __tablename__ = "captures"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    stored_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source: Mapped[str] = mapped_column(String(64), default="upload")  # upload | live
    status: Mapped[str] = mapped_column(String(32), default="created")
    # created | queued | analyzing | completed | failed | stopped
    start_time: Mapped[float | None] = mapped_column(Float, nullable=True)
    end_time: Mapped[float | None] = mapped_column(Float, nullable=True)
    first_packet_ts: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_packet_ts: Mapped[float | None] = mapped_column(Float, nullable=True)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    analyzed_packet_count: Mapped[int] = mapped_column(Integer, default=0)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    analysis_progress: Mapped[int] = mapped_column(Integer, default=0)  # 0..100
    parser_used: Mapped[str | None] = mapped_column(String(32), nullable=True)
    link_type: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(default=None)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)  # protocol counts etc.


class FlowModel(Base):
    __tablename__ = "flows"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    capture_id: Mapped[str] = mapped_column(String(32), index=True)
    source_ip: Mapped[str] = mapped_column(String(64))
    destination_ip: Mapped[str] = mapped_column(String(64))
    source_port: Mapped[int] = mapped_column(Integer)
    destination_port: Mapped[int] = mapped_column(Integer)
    transport_protocol: Mapped[str] = mapped_column(String(16))  # TCP | UDP
    application_protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)
    first_seen: Mapped[float] = mapped_column(Float)
    last_seen: Mapped[float] = mapped_column(Float)
    packets: Mapped[int] = mapped_column(Integer, default=0)
    bytes: Mapped[int] = mapped_column(Integer, default=0)
    packets_forward: Mapped[int] = mapped_column(Integer, default=0)
    bytes_forward: Mapped[int] = mapped_column(Integer, default=0)
    packets_reverse: Mapped[int] = mapped_column(Integer, default=0)
    bytes_reverse: Mapped[int] = mapped_column(Integer, default=0)
    duration: Mapped[float] = mapped_column(Float, default=0.0)
    direction: Mapped[str] = mapped_column(String(16), default="outbound")  # outbound|inbound|internal|unknown
    tcp_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    retransmissions: Mapped[int] = mapped_column(Integer, default=0)
    resets: Mapped[int] = mapped_column(Integer, default=0)
    syn_count: Mapped[int] = mapped_column(Integer, default=0)
    syn_retransmissions: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[bool] = mapped_column(Integer, default=False)  # no SYN-ACK answered SYN
    packet_refs: Mapped[list] = mapped_column(JSON, default=list)  # normalized packet indices
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class HostModel(Base):
    __tablename__ = "hosts"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    capture_id: Mapped[str] = mapped_column(String(32), index=True)
    ip: Mapped[str] = mapped_column(String(64))
    mac: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_internal: Mapped[bool] = mapped_column(Integer, default=False)
    first_seen: Mapped[float] = mapped_column(Float)
    last_seen: Mapped[float] = mapped_column(Float)
    packets_sent: Mapped[int] = mapped_column(Integer, default=0)
    packets_received: Mapped[int] = mapped_column(Integer, default=0)
    bytes_sent: Mapped[int] = mapped_column(Integer, default=0)
    bytes_received: Mapped[int] = mapped_column(Integer, default=0)
    protocols: Mapped[dict] = mapped_column(JSON, default=dict)  # {proto: packets}
    services: Mapped[list] = mapped_column(JSON, default=list)  # exposed ports [{port, proto, first_seen}]
    contacted: Mapped[list] = mapped_column(JSON, default=list)  # [{ip, port, app_proto, packets}]
    role: Mapped[str | None] = mapped_column(String(64), nullable=True)  # inferred role
    behavior_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class DNSTransactionModel(Base):
    __tablename__ = "dns_transactions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    capture_id: Mapped[str] = mapped_column(String(32), index=True)
    transaction_id: Mapped[int] = mapped_column(Integer)  # DNS txid
    client_ip: Mapped[str] = mapped_column(String(64))
    server_ip: Mapped[str] = mapped_column(String(64))
    query_name: Mapped[str] = mapped_column(String(512))
    query_type: Mapped[int | None] = mapped_column(String(16), nullable=True)
    response_ips: Mapped[list] = mapped_column(JSON, default=list)
    is_response: Mapped[bool] = mapped_column(Integer, default=False)
    rcode: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency: Mapped[float | None] = mapped_column(Float, nullable=True)  # query→response seconds
    timestamp: Mapped[float] = mapped_column(Float)
    packet_ref: Mapped[int] = mapped_column(Integer, default=0)


class HTTPTransactionModel(Base):
    __tablename__ = "http_transactions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    capture_id: Mapped[str] = mapped_column(String(32), index=True)
    client_ip: Mapped[str] = mapped_column(String(64))
    server_ip: Mapped[str] = mapped_column(String(64))
    server_port: Mapped[int] = mapped_column(Integer, default=80)
    method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    request_len: Mapped[int] = mapped_column(Integer, default=0)
    response_len: Mapped[int] = mapped_column(Integer, default=0)
    timestamp: Mapped[float] = mapped_column(Float)
    packet_ref: Mapped[int] = mapped_column(Integer, default=0)


class TLSSessionModel(Base):
    __tablename__ = "tls_sessions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    capture_id: Mapped[str] = mapped_column(String(32), index=True)
    client_ip: Mapped[str] = mapped_column(String(64))
    server_ip: Mapped[str] = mapped_column(String(64))
    server_port: Mapped[int] = mapped_column(Integer, default=443)
    sni: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    bytes: Mapped[int] = mapped_column(Integer, default=0)
    packets: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[float] = mapped_column(Float)
    last_seen: Mapped[float] = mapped_column(Float)
    packet_refs: Mapped[list] = mapped_column(JSON, default=list)


class AlertModel(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    capture_id: Mapped[str] = mapped_column(String(32), index=True)
    rule_name: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16))  # critical|high|medium|low|info
    score: Mapped[int] = mapped_column(Integer)  # 0..100
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reasons: Mapped[list] = mapped_column(JSON, default=list)  # [{"reason": str, "detail": str, "weight": int}]
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)  # rule-specific proof data
    related_flow_ids: Mapped[list] = mapped_column(JSON, default=list)
    related_packet_refs: Mapped[list] = mapped_column(JSON, default=list)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    acknowledged: Mapped[bool] = mapped_column(Integer, default=False)
    tags: Mapped[list] = mapped_column(JSON, default=list)  # triage labels: confirmed | false-positive | escalated
    note: Mapped[str | None] = mapped_column(Text, nullable=True)  # free-text analyst note
    timestamp: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class TimelineEventModel(Base):
    __tablename__ = "timeline_events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    capture_id: Mapped[str] = mapped_column(String(32), index=True)
    event_type: Mapped[str] = mapped_column(String(32))  # dns_query|dns_response|tcp_connect|http_request|tls_handshake|alert|flow_failed|scan
    label: Mapped[str] = mapped_column(String(255))
    timestamp: Mapped[float] = mapped_column(Float, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(512), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    related_flow_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    related_alert_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    packet_ref: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class AnalysisJobModel(Base):
    __tablename__ = "analysis_jobs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    capture_id: Mapped[str] = mapped_column(String(32), index=True)
    type: Mapped[str] = mapped_column(String(32), default="full_analysis")
    status: Mapped[str] = mapped_column(String(32), default="queued")
    # queued | running | completed | failed
    progress: Mapped[int] = mapped_column(Integer, default=0)
    stage: Mapped[str] = mapped_column(String(64), default="queued")
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)
    result: Mapped[dict] = mapped_column(JSON, default=dict)


class PacketModel(Base):
    """Persisted normalized packet — the packet store for evidence drill-down.

    Written once at analysis time so evidence/stats endpoints never re-parse the PCAP.
    """

    __tablename__ = "packets"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    capture_id: Mapped[str] = mapped_column(String(32), index=True)
    packet_reference: Mapped[int] = mapped_column(Integer, index=True)  # ordinal in capture
    timestamp: Mapped[float] = mapped_column(Float)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)
    transport: Mapped[str | None] = mapped_column(String(16), nullable=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    length: Mapped[int] = mapped_column(Integer, default=0)
    flags: Mapped[list] = mapped_column(JSON, default=list)
    meta: Mapped[dict] = mapped_column("metadata", JSON, default=dict)  # 'metadata' reserved in SQLAlchemy


class CaseModel(Base):
    """An investigation case — groups related captures into one incident."""

    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    capture_ids: Mapped[list] = mapped_column(JSON, default=list)  # ordered capture id list
    status: Mapped[str] = mapped_column(String(32), default="open")  # open | closed
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime | None] = mapped_column(default=None)
