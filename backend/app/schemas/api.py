"""API request/response schemas (separate from ORM + internal models)."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CaptureOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    filename: str
    stored_path: str | None = None
    source: str
    status: str
    start_time: float | None = None
    end_time: float | None = None
    first_packet_ts: float | None = None
    last_packet_ts: float | None = None
    packet_count: int
    analyzed_packet_count: int
    size_bytes: int
    analysis_progress: int
    parser_used: str | None = None
    error: str | None = None
    created_at: datetime
    completed_at: datetime | None = None
    summary: dict[str, Any] = Field(default_factory=dict)


class JobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    capture_id: str
    type: str
    status: str
    progress: int
    stage: str
    message: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    result: dict[str, Any] = Field(default_factory=dict)


class AnalyzeRequest(BaseModel):
    parser: str | None = None  # None => auto ("scapy" preferred, "tshark" if requested+available)


class Page(BaseModel):
    """Pagination envelope: items + total + offset so UIs can build page controls."""

    items: list[Any]
    total: int
    offset: int
    limit: int

    @classmethod
    def of(cls, items: list, total: int, offset: int, limit: int) -> Page:
        return cls(items=items, total=total, offset=offset, limit=limit)


class FlowOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    capture_id: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    transport_protocol: str
    application_protocol: str | None = None
    first_seen: float
    last_seen: float
    packets: int
    bytes: int
    packets_forward: int
    bytes_forward: int
    packets_reverse: int
    bytes_reverse: int
    duration: float
    direction: str
    tcp_state: str | None = None
    retransmissions: int
    resets: int
    syn_count: int
    syn_retransmissions: int
    failed: bool
    created_at: datetime


class PacketEvidence(BaseModel):
    timestamp: float
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: str | None = None
    transport: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    length: int = 0
    flags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    packet_reference: int = 0


class FlowDetailOut(FlowOut):
    packet_evidence: list[PacketEvidence] = Field(default_factory=list)


class HostOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    capture_id: str
    ip: str
    mac: str | None = None
    hostname: str | None = None
    is_internal: bool
    first_seen: float
    last_seen: float
    packets_sent: int
    packets_received: int
    bytes_sent: int
    bytes_received: int
    protocols: dict[str, int] = Field(default_factory=dict)
    services: list[dict[str, Any]] = Field(default_factory=list)
    contacted: list[dict[str, Any]] = Field(default_factory=list)
    role: str | None = None
    behavior_summary: dict[str, Any] = Field(default_factory=dict)


class DNSTransactionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    capture_id: str
    transaction_id: int
    client_ip: str
    server_ip: str
    query_name: str
    query_type: str | None = None
    response_ips: list[str] = Field(default_factory=list)
    is_response: bool
    rcode: int | None = None
    latency: float | None = None
    timestamp: float
    packet_ref: int


class HTTPTransactionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    capture_id: str
    client_ip: str
    server_ip: str
    server_port: int
    method: str | None = None
    host: str | None = None
    path: str | None = None
    user_agent: str | None = None
    status_code: int | None = None
    request_len: int
    response_len: int
    timestamp: float
    packet_ref: int


class TLSSessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    capture_id: str
    client_ip: str
    server_ip: str
    server_port: int
    sni: str | None = None
    version: str | None = None
    bytes: int
    packets: int
    first_seen: float
    last_seen: float


class ProtocolStatsOut(BaseModel):
    dns: dict[str, Any] = Field(default_factory=dict)
    http: dict[str, Any] = Field(default_factory=dict)


class AlertReason(BaseModel):
    reason: str
    detail: str
    weight: int


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    capture_id: str
    rule_name: str
    title: str
    severity: str
    score: int
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    reasons: list[AlertReason] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    related_flow_ids: list[str] = Field(default_factory=list)
    related_packet_refs: list[int] = Field(default_factory=list)
    explanation: str | None = None
    acknowledged: bool
    tags: list[str] = Field(default_factory=list)
    note: str | None = None
    timestamp: float | None = None
    created_at: datetime


class CaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: str | None = None
    capture_ids: list[str] = Field(default_factory=list)
    status: str
    created_at: datetime
    updated_at: datetime | None = None


class CaseDetailOut(CaseOut):
    """Case with its captures and aggregated stats resolved."""

    captures: list[CaptureOut] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)


class CaseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4000)


class CaseCaptureBody(BaseModel):
    capture_id: str


class TimelineEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    capture_id: str
    event_type: str
    label: str
    timestamp: float
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None
    domain: str | None = None
    severity: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)
    related_flow_id: str | None = None
    related_alert_id: str | None = None
    packet_ref: int | None = None


class GraphElementData(BaseModel):
    id: str
    label: str | None = None
    type: str | None = None
    source: str | None = None
    target: str | None = None
    packets: int | None = None
    bytes: int | None = None
    count: int | None = None
    role: str | None = None
    hostname: str | None = None
    internal: bool | None = None
    port: int | None = None
    service: str | None = None
    alert_count: int | None = None
    flow_ids: list[str] | None = None


class GraphElement(BaseModel):
    data: GraphElementData
    position: dict[str, float] | None = None


class GraphOut(BaseModel):
    nodes: list[GraphElement]
    edges: list[GraphElement]
    stats: dict[str, Any] = Field(default_factory=dict)


# ---- Evidence Graph 2.0 (v2) -------------------------------------------------


class GraphV2Node(BaseModel):
    """Hydrated node — metadata comes from the owning source table."""

    id: str
    kind: str  # host | domain | service | alert | incident | case | capture
    label: str
    ip: str | None = None
    internal: bool | None = None
    role: str | None = None
    hostname: str | None = None
    port: int | None = None
    first_seen: float | None = None
    last_seen: float | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None
    alert_count: int | None = None
    rule_name: str | None = None
    severity: str | None = None
    score: int | None = None
    reasons: list[dict[str, Any]] = Field(default_factory=list)
    explanation: str | None = None
    mitre: dict[str, str | None] | None = None
    status: str | None = None
    filename: str | None = None
    packet_count: int | None = None


class GraphV2Edge(BaseModel):
    """Evidence-backed relationship with full provenance."""

    id: str
    source: str
    target: str
    relationship: str
    provenance: str  # observed | correlated | enriched
    first_seen: float
    last_seen: float
    count: int = 0
    packets: int = 0
    bytes: int = 0
    protocol: str | None = None
    port: int | None = None
    flow_ids: list[str] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
    packet_refs: list[int] = Field(default_factory=list)
    explanation: str | None = None
    # evidence summary (edge detail endpoint)
    flows: list[dict[str, Any]] = Field(default_factory=list)
    alerts: list[dict[str, Any]] = Field(default_factory=list)


class GraphV2Out(BaseModel):
    nodes: list[GraphV2Node]
    edges: list[GraphV2Edge]
    stats: dict[str, Any] = Field(default_factory=dict)
    truncated: bool = False


class GraphV2NodeOut(BaseModel):
    node: GraphV2Node
    edges: list[GraphV2Edge]
    stats: dict[str, Any] = Field(default_factory=dict)


class GraphV2Path(BaseModel):
    nodes: list[str]
    length: int


class GraphV2PathsOut(BaseModel):
    paths: list[GraphV2Path]
    visited: int = 0
    truncated: bool = False
    reason: str | None = None


class GraphV2BlastOut(BaseModel):
    start: str
    depth: int
    nodes: list[str]
    rings: dict[str, list[str]] = Field(default_factory=dict)
    edges: list[dict[str, Any]] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    truncated: bool = False
    reason: str | None = None
