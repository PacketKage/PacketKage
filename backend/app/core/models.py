"""Normalized internal data model — parser-agnostic.

Parser-specific objects (Scapy packets, TShark JSON) never leave the parser layer.
Everything downstream works with these normalized structures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class NormalizedPacket:
    """Parser-agnostic packet summary."""

    timestamp: float
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: str | None = None  # highest-level protocol detected
    transport: str | None = None  # TCP / UDP / ICMP / ...
    source_port: int | None = None
    destination_port: int | None = None
    length: int = 0
    flags: list[str] = field(default_factory=list)  # e.g. ["SYN", "ACK"]
    metadata: dict[str, Any] = field(
        default_factory=dict
    )  # protocol hints (dns.query, http.host, tls.sni, ...)
    packet_reference: int = 0  # index/ordinal in capture for later evidence drill-down


@dataclass
class ParsedCapture:
    """Result of parsing a capture file: normalized packets + capture-level metadata."""

    filename: str
    packets: list[NormalizedPacket] = field(default_factory=list)
    link_type: int | None = None
    parser_used: str = "unknown"
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
