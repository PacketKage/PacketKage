"""Flow reconstruction — groups normalized packets into bidirectional conversations.

A flow is a canonical 5-tuple (min(ip,port) side first) so both directions of a
conversation land in the same flow, with forward/reverse counters tracked separately.

Evidence: each flow keeps packet_refs (indices into the normalized packet list)
so Flow -> related packets is a pure lookup, no re-parsing.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from app.core.models import NormalizedPacket

# IPv6 networks considered "internal" for traffic analysis purposes.
# We intentionally avoid stdlib ``is_private`` which (since Python 3.11)
# includes 2001:db8::/32 (documentation) and 100::/64 (discard), neither
# of which represents a real internal network.
_INTERNAL_V6_NETS = (
    ipaddress.IPv6Network("::1/128"),        # loopback
    ipaddress.IPv6Network("fc00::/7"),        # unique-local (ULA)
    ipaddress.IPv6Network("fe80::/10"),       # link-local
)


def _is_internal_v6(addr: ipaddress.IPv6Address) -> bool:
    """Return True when *addr* belongs to a non-routable / internal-network range."""
    # IPv4-mapped addresses (::ffff:x.x.x.x) — delegate to the embedded v4 check.
    mapped = addr.ipv4_mapped
    if mapped is not None:
        return mapped.is_loopback or mapped.is_private
    return any(addr in net for net in _INTERNAL_V6_NETS)


# RFC-1918 private IPv4 networks (excludes TEST-NET / documentation ranges)
_INTERNAL_V4_NETS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),        # loopback
    ipaddress.IPv4Network("169.254.0.0/16"),     # link-local
    ipaddress.IPv4Network("100.64.0.0/10"),      # carrier-grade NAT
)


def is_private_ip(ip: str | None) -> bool:
    """Return True when *ip* is a loopback, link-local, or RFC-1918 / ULA address.

    Handles IPv4, IPv6, and IPv4-mapped IPv6 (``::ffff:10.0.0.1``)
    addresses correctly.

    Unlike stdlib ``is_private``, this EXCLUDES documentation ranges
    (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) which are routable
    public addresses reserved for examples.
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        return _is_internal_v6(addr)
    # IPv4: check against RFC-1918 + loopback + link-local + CGNAT only
    return any(addr in net for net in _INTERNAL_V4_NETS)


@dataclass
class TCPSequencer:
    """Per-flow TCP sequencing for retransmission/reset detection."""

    syn_count: int = 0
    syn_retransmissions: int = 0
    data_retransmissions: int = 0
    resets: int = 0
    saw_syn: bool = False
    saw_synack: bool = False
    saw_fin: bool = False
    # per-direction last sequence info: (direction_key) -> last ack-carrying seq
    last_seq: dict[str, int] = field(default_factory=dict)

    def observe(self, pkt: NormalizedPacket, forward: bool) -> None:
        flags = pkt.flags
        if "RST" in flags:
            self.resets += 1
        if "SYN" in flags:
            self.syn_count += 1
            if "ACK" not in flags:
                if self.saw_syn:
                    self.syn_retransmissions += 1
                self.saw_syn = True
            else:
                self.saw_synack = True
        if "FIN" in flags:
            self.saw_fin = True

        if "ACK" in flags and "SYN" not in flags and pkt.metadata.get("seq") is not None:
            key = "f" if forward else "r"
            seq = pkt.metadata["seq"]
            # retransmission: same seq repeated with ACK (no payload info in v1) or seq went backwards
            prev = self.last_seq.get(key)
            if prev is not None and seq < prev:
                self.data_retransmissions += 1
            self.last_seq[key] = seq

    @property
    def state(self) -> str | None:
        if self.resets:
            return "reset"
        if self.saw_fin:
            return "closed"
        if self.saw_synack:
            return "established"
        if self.saw_syn:
            return "half_open"
        return None


@dataclass
class _FlowAccumulator:
    key: tuple
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    transport: str
    first_seen: float
    last_seen: float
    packets: int = 0
    bytes: int = 0
    packets_forward: int = 0
    bytes_forward: int = 0
    packets_reverse: int = 0
    bytes_reverse: int = 0
    app_protocol: str | None = None
    app_votes: dict[str, int] = field(default_factory=dict)
    sequencer: TCPSequencer | None = None
    packet_refs: list[int] = field(default_factory=list)

    def add(self, pkt: NormalizedPacket, forward: bool) -> None:
        self.packets += 1
        self.bytes += pkt.length
        if forward:
            self.packets_forward += 1
            self.bytes_forward += pkt.length
        else:
            self.packets_reverse += 1
            self.bytes_reverse += pkt.length
        self.first_seen = min(self.first_seen, pkt.timestamp)
        self.last_seen = max(self.last_seen, pkt.timestamp)
        if pkt.protocol and pkt.protocol not in ("TCP", "UDP", "IP"):
            self.app_votes[pkt.protocol] = self.app_votes.get(pkt.protocol, 0) + 1
        self.packet_refs.append(pkt.packet_reference)
        if self.transport == "TCP" and self.sequencer:
            self.sequencer.observe(pkt, forward)

    @property
    def application_protocol(self) -> str | None:
        if self.app_votes:
            return max(self.app_votes, key=self.app_votes.get)
        return None

    @property
    def direction(self) -> str:
        src_priv = is_private_ip(self.source_ip)
        dst_priv = is_private_ip(self.destination_ip)
        if src_priv and not dst_priv:
            return "outbound"
        if dst_priv and not src_priv:
            return "inbound"
        if src_priv and dst_priv:
            return "internal"
        return "unknown"


class FlowBuilder:
    """Aggregates a stream of normalized packets into flows."""

    def __init__(self) -> None:
        self._flows: dict[tuple, _FlowAccumulator] = {}

    def build_from(self, parsed) -> list[dict]:
        """Convenience: build flows from a ParsedCapture."""
        for pkt in parsed.packets:
            self.add_packet(pkt)
        return self.build()

    def add_packet(self, pkt: NormalizedPacket) -> None:
        if pkt.transport not in ("TCP", "UDP"):
            return  # v1: flows are transport conversations only
        if not pkt.source_ip or not pkt.destination_ip:
            return
        if pkt.source_port is None or pkt.destination_port is None:
            return

        flow_key = self._canonical_key(pkt)
        forward = (pkt.source_ip, pkt.source_port) == flow_key[0]
        flow = self._flows.get(flow_key)
        if flow is None:
            # initiator (first-seen endpoint) defines flow source/destination
            flow = _FlowAccumulator(
                key=flow_key,
                source_ip=pkt.source_ip,
                destination_ip=pkt.destination_ip,
                source_port=pkt.source_port,
                destination_port=pkt.destination_port,
                transport=pkt.transport,
                first_seen=pkt.timestamp,
                last_seen=pkt.timestamp,
                sequencer=TCPSequencer() if pkt.transport == "TCP" else None,
            )
            self._flows[flow_key] = flow
        flow.add(pkt, forward)

    def _canonical_key(self, pkt: NormalizedPacket) -> tuple[tuple, bool]:
        a = (pkt.source_ip, pkt.source_port)
        b = (pkt.destination_ip, pkt.destination_port)
        lo, hi = (a, b) if a <= b else (b, a)
        return (lo, hi, pkt.transport)

    def build(self) -> list[dict]:
        """Return flow dicts ordered by first_seen, ready for persistence."""
        results = []
        for acc in self._flows.values():
            failed = (
                acc.transport == "TCP"
                and acc.sequencer is not None
                and acc.sequencer.syn_count > 0
                and not acc.sequencer.saw_synack
            )
            results.append(
                {
                    "source_ip": acc.source_ip,
                    "destination_ip": acc.destination_ip,
                    "source_port": acc.source_port,
                    "destination_port": acc.destination_port,
                    "transport_protocol": acc.transport,
                    "application_protocol": acc.application_protocol,
                    "first_seen": acc.first_seen,
                    "last_seen": acc.last_seen,
                    "packets": acc.packets,
                    "bytes": acc.bytes,
                    "packets_forward": acc.packets_forward,
                    "bytes_forward": acc.bytes_forward,
                    "packets_reverse": acc.packets_reverse,
                    "bytes_reverse": acc.bytes_reverse,
                    "duration": acc.last_seen - acc.first_seen,
                    "direction": acc.direction,
                    "tcp_state": acc.sequencer.state if acc.sequencer else None,
                    "retransmissions": (
                        (acc.sequencer.data_retransmissions + acc.sequencer.syn_retransmissions)
                        if acc.sequencer
                        else 0
                    ),
                    "resets": acc.sequencer.resets if acc.sequencer else 0,
                    "syn_count": acc.sequencer.syn_count if acc.sequencer else 0,
                    "syn_retransmissions": acc.sequencer.syn_retransmissions if acc.sequencer else 0,
                    "failed": failed,
                    "packet_refs": acc.packet_refs,
                }
            )
        results.sort(key=lambda f: f["first_seen"])
        return results
