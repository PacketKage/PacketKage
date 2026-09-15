"""Evidence Graph 2.0 — materialized, provenance-carrying relationship graph.

Architecture (follows the Timeline precedent: derived at analysis time,
persisted, then queried with SQL filters/caps):

- Nodes are STABLE STRING IDS hydrated from existing tables at query time
  (no data duplication): host:{ip}, domain:{name}, service:{ip}:{port},
  alert:{id}, incident:{source_ip}, case:{id}.
- Edges are persisted rows in graph_edges, each carrying provenance:
  relationship type, provenance class (observed | correlated | enriched),
  first/last seen, protocol/port where applicable, and the evidence IDs
  (flows/alerts/packets) that back it — all capped to stay bounded.
- Suspicious-edge explanations are deterministic aggregations of the REAL
  alerts touching a pair — no invented scores, no fake intel.
- Attack Path and Blast Radius are QUERY-TIME inferences over observed
  edges, never persisted as facts. They are strictly bounded.

Provenance classes:
  observed   — directly seen in packet-derived artifacts (flows, DNS, TLS, HTTP)
  correlated — derived by deterministic correlation (incidents → alerts)
  enriched   — static enrichment clearly labeled as such (MITRE technique map)

Nothing here invents evidence: if an edge has no alert evidence, its
explanation is None; if a technique has no matching rule, it is not shown.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.orm import (
    AlertModel,
    CaptureModel,
    CaseModel,
    DNSTransactionModel,
    FlowModel,
    GraphEdgeModel,
    HostModel,
    HTTPTransactionModel,
    TLSSessionModel,
)

# ---- Node ID helpers -------------------------------------------------------


def host_id(ip: str) -> str:
    return f"host:{ip}"


def domain_id(name: str) -> str:
    return f"domain:{(name or '').rstrip('.')}"


def service_id(ip: str, port: int) -> str:
    return f"service:{ip}:{port}"


def alert_id(aid: str) -> str:
    return f"alert:{aid}"


def incident_id(source_ip: str) -> str:
    return f"incident:{source_ip}"


def case_id(cid: str) -> str:
    return f"case:{cid}"


def capture_id(cid: str) -> str:
    return f"capture:{cid}"


def parse_node_id(raw: str) -> tuple[str, str]:
    """Split a graph node id into (kind, key) — e.g. 'host:10.0.0.1' → ('host', '10.0.0.1')."""
    kind, _, key = raw.partition(":")
    return kind, key


# ---- Caps (bounded by design) ----------------------------------------------


class GraphCaps:
    """Hard bounds so /api/graph/v2 can never become an unbounded operation."""

    # build-time provenance caps (per edge row)
    MAX_FLOW_REFS = 100
    MAX_ALERT_REFS = 50
    MAX_PACKET_REFS = 100

    # query-time subgraph caps
    DEFAULT_NODE_LIMIT = 300
    HARD_NODE_LIMIT = 1000

    # attack-path traversal bounds
    MAX_PATH_DEPTH = 4
    MAX_PATHS = 3
    PATH_NODE_CAP = 200

    # blast-radius bounds
    MAX_BLAST_DEPTH = 3
    BLAST_NODE_CAP = 150
    BLAST_HARD_NODE_CAP = 500


# ---- MITRE enrichment (static, curated, labeled as enrichment) --------------
# Maps the 14 existing deterministic rules to ATT&CK context. This is
# enrichment of REAL detections — shown as chips on alert-backed items only.
#
# Every entry declares its source:
#   "mitre"      — defensible official ATT&CK technique/sub-technique mapping;
#                 technique_id matches ^T\d{4}(\.\d{3})?$
#   "packetkage" — PacketKage internal classification: the captured evidence
#                 does not establish a specific official ATT&CK technique, so
#                 no technique_id is emitted. Internal identifiers (e.g.
#                 "C1091") must never be rendered as ATT&CK IDs.

RULE_MITRE: dict[str, dict[str, str | None]] = {
    "port_scan": {
        "technique_id": "T1046",
        "technique": "Network Service Discovery",
        "tactic": "Discovery",
        "source": "mitre",
    },
    "beaconing": {
        "technique_id": None,  # no official ATT&CK number for periodicity itself
        "technique": "Scheduled Beaconing",
        "tactic": "Command and Control",
        "source": "packetkage",
    },
    "dns_tunneling": {
        "technique_id": "T1071.004",
        "technique": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "source": "mitre",
    },
    "nxdomain_burst": {
        "technique_id": None,  # NXDOMAIN burst does not establish DNS-as-C2-channel
        "technique": "NXDOMAIN Burst",
        "tactic": "Command and Control",
        "source": "packetkage",
    },
    "suspicious_port": {
        "technique_id": "T1571",
        "technique": "Non-Standard Port",
        "tactic": "Command and Control",
        "source": "mitre",
    },
    "excessive_connection_failures": {
        "technique_id": None,  # failed connections are not network service discovery
        "technique": "Excessive Connection Failures",
        "tactic": "Command and Control",
        "source": "packetkage",
    },
    "connection_without_dns": {
        "technique_id": None,  # direct-IP connection does not establish an encrypted channel
        "technique": "Direct-IP Connection",
        "tactic": "Command and Control",
        "source": "packetkage",
    },
    "high_outbound_volume": {
        "technique_id": None,  # volume alone does not establish an exfiltration mechanism
        "technique": "High Outbound Volume",
        "tactic": "Exfiltration",
        "source": "packetkage",
    },
    "arp_spoofing": {
        "technique_id": "T1557.002",
        "technique": "Adversary-in-the-Middle: ARP Cache Poisoning",
        "tactic": "Collection",
        "source": "mitre",
    },
    "lateral_movement": {
        "technique_id": "T1021",
        "technique": "Remote Services",
        "tactic": "Lateral Movement",
        "source": "mitre",
    },
    "dga_domain": {
        "technique_id": "T1568.002",
        "technique": "Domain Generation Algorithms",
        "tactic": "Command and Control",
        "source": "mitre",
    },
    "data_exfiltration": {
        "technique_id": "T1048",
        "technique": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "source": "mitre",
    },
    "low_slow_beaconing": {
        "technique_id": None,  # no official ATT&CK number for periodicity itself
        "technique": "Low-and-Slow Beaconing",
        "tactic": "Command and Control",
        "source": "packetkage",
    },
    "suspicious_user_agent": {
        "technique_id": None,  # retired T1043 was never a defensible mapping for a suspicious UA
        "technique": "Suspicious User Agent",
        "tactic": "Command and Control",
        "source": "packetkage",
    },
}


# ---- Edge accumulator -------------------------------------------------------


@dataclass
class _EdgeAcc:
    """Aggregates evidence into one (source, target, relationship) edge."""

    first_seen: float | None = None
    last_seen: float | None = None
    count: int = 0
    packets: int = 0
    bytes: int = 0
    protocol: str | None = None
    port: int | None = None
    flow_ids: list[str] = field(default_factory=list)
    alert_ids: list[str] = field(default_factory=list)
    packet_refs: list[int] = field(default_factory=list)
    provenance: str = "observed"
    explanation: str | None = None

    def observe(
        self,
        ts: float,
        *,
        packets: int = 0,
        bytes_: int = 0,
        protocol: str | None = None,
        port: int | None = None,
        flow_id: str | None = None,
        alert_id: str | None = None,
        packet_ref: int | None = None,
    ) -> None:
        self.count += 1
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts
        self.packets += packets
        self.bytes += bytes_
        if self.protocol is None and protocol:
            self.protocol = protocol
        if self.port is None and port is not None:
            self.port = port
        if flow_id and flow_id not in self.flow_ids:
            self.flow_ids.append(flow_id)
        if alert_id and alert_id not in self.alert_ids:
            self.alert_ids.append(alert_id)
        if packet_ref is not None and packet_ref not in self.packet_refs:
            self.packet_refs.append(packet_ref)


class EvidenceGraphBuilder:
    """Builds evidence-graph edges for one capture from persisted artifacts."""

    def __init__(self, db: Session) -> None:
        self.db = db

    # -- suspicious-edge explanation: deterministic aggregation of real alerts --

    def _alert_context(self, capture_id: str) -> dict[tuple[str, str], list[AlertModel]]:
        """(src_ip, dst_ip) → alerts touching that ordered pair (both directions grouped)."""
        alerts = list(
            self.db.scalars(
                select(AlertModel)
                .where(AlertModel.capture_id == capture_id)
                .order_by(AlertModel.score.desc())
            )
        )
        by_pair: dict[tuple[str, str], list[AlertModel]] = defaultdict(list)
        for a in alerts:
            if a.source_ip and a.destination_ip:
                by_pair[(a.source_ip, a.destination_ip)].append(a)
        return by_pair

    @staticmethod
    def _explain(alerts: list[AlertModel]) -> str | None:
        """Deterministic explanation from actual alerts — None when no alert evidence."""
        if not alerts:
            return None
        rules = sorted({a.rule_name for a in alerts})
        worst = max(alerts, key=lambda a: a.score)
        sev_counts: dict[str, int] = defaultdict(int)
        for a in alerts:
            sev_counts[a.severity] += 1
        sev_text = ", ".join(f"{n} {s}" for s, n in sorted(sev_counts.items()))
        return (
            f"{len(alerts)} alert(s) touch this relationship: {', '.join(rules)}. "
            f"Highest-scoring: [{worst.severity.upper()}] {worst.title} (score {worst.score}). "
            f"Severity mix: {sev_text}. Explanations below are drawn from these alerts only."
        )

    # -- main build --

    def build(self, capture: CaptureModel) -> list[GraphEdgeModel]:
        cap_id = capture.id
        edges: dict[tuple[str, str, str], _EdgeAcc] = {}

        def acc(src: str, dst: str, rel: str, provenance: str = "observed") -> _EdgeAcc:
            key = (src, dst, rel)
            if key not in edges:
                edges[key] = _EdgeAcc(provenance=provenance)
            return edges[key]

        flows = list(
            self.db.scalars(
                select(FlowModel).where(FlowModel.capture_id == cap_id)
            )
        )
        dns_txns = list(
            self.db.scalars(
                select(DNSTransactionModel).where(DNSTransactionModel.capture_id == cap_id)
            )
        )
        tls_sessions = list(
            self.db.scalars(
                select(TLSSessionModel).where(TLSSessionModel.capture_id == cap_id)
            )
        )
        http_txns = list(
            self.db.scalars(
                select(HTTPTransactionModel).where(HTTPTransactionModel.capture_id == cap_id)
            )
        )
        hosts = list(
            self.db.scalars(select(HostModel).where(HostModel.capture_id == cap_id))
        )
        alerts = list(
            self.db.scalars(
                select(AlertModel)
                .where(AlertModel.capture_id == cap_id)
                .order_by(AlertModel.score.desc())
            )
        )
        alert_by_pair = self._alert_context(cap_id)

        # 1) FLOW edges (host → host): directly observed, flow+packet provenance
        for f in flows:
            src, dst = host_id(f.source_ip), host_id(f.destination_ip)
            e = acc(src, dst, "FLOW")
            refs = [int(r) for r in (f.packet_refs or [])[: GraphCaps.MAX_PACKET_REFS]]
            # ONE observation per flow: refs are evidence detail, not new events
            e.observe(
                f.first_seen,
                packets=f.packets,
                bytes_=f.bytes,
                protocol=f.application_protocol or f.transport_protocol,
                port=f.destination_port,
                flow_id=f.id,
                packet_ref=refs[0] if refs else None,
            )
            for ref in refs[1:]:
                if ref not in e.packet_refs:
                    e.packet_refs.append(ref)

        # 2) DNS edges (client → domain), plus RESOLVES_TO (domain → ip)
        for t in dns_txns:
            name = (t.query_name or "").rstrip(".")
            if not name:
                continue
            e = acc(host_id(t.client_ip), domain_id(name), "DNS_QUERY")
            e.observe(
                t.timestamp,
                protocol="DNS",
                port=53,
                packet_ref=t.packet_ref if t.packet_ref else None,
            )
            for ip in (t.response_ips or [])[:10]:
                r = acc(domain_id(name), host_id(ip), "RESOLVES_TO")
                r.observe(t.timestamp, protocol="DNS")

        # 3) TLS SNI edges (client → domain)
        for s in tls_sessions:
            if s.sni:
                e = acc(host_id(s.client_ip), domain_id(s.sni), "TLS_SNI")
                e.observe(
                    s.first_seen,
                    packets=s.packets,
                    bytes_=s.bytes,
                    protocol="TLS",
                    port=s.server_port,
                )
                # SNI domain also resolves-to the server when a DNS answer
                # was observed — but keep them separate: the SNI edge itself
                # does not assert resolution. A RESOLVES_TO edge only exists
                # when a DNS response actually carried that IP (case 2).

        # 4) HTTP Host header edges (client → domain)
        for t in http_txns:
            if t.host:
                e = acc(host_id(t.client_ip), domain_id(t.host), "HTTP_HOST")
                e.observe(
                    t.timestamp,
                    protocol="HTTP",
                    port=t.server_port,
                    packet_ref=t.packet_ref if t.packet_ref else None,
                )

        # 5) EXPOSES edges (host → service)
        for h in hosts:
            for svc in (h.services or [])[:15]:  # same cap as v1
                e = acc(host_id(h.ip), service_id(h.ip, int(svc["port"])), "EXPOSES")
                e.observe(
                    h.first_seen,
                    protocol=str(svc.get("transport") or "TCP/UDP"),
                    port=int(svc["port"]),
                )

        # 6) Alert edges (alert → targets) + alert attribution onto FLOW edges
        for a in alerts:
            if not a.source_ip:
                continue
            # alert → source host (which host triggered it)
            e = acc(alert_id(a.id), host_id(a.source_ip), "TRIGGERED", provenance="correlated")
            e.observe(a.timestamp or 0.0, alert_id=a.id)
            if a.destination_ip:
                # alert → destination host (whom it targeted)
                t = acc(alert_id(a.id), host_id(a.destination_ip), "TARGETS", provenance="correlated")
                t.observe(a.timestamp or 0.0, alert_id=a.id, port=a.destination_port)

            # attribute alert evidence onto the FLOW edge it describes
            pair = (a.source_ip, a.destination_ip)
            flow_edge = edges.get((host_id(a.source_ip), host_id(a.destination_ip), "FLOW"))
            if flow_edge is None:
                continue
            if a.id not in flow_edge.alert_ids:
                flow_edge.alert_ids.append(a.id)
            for other in alert_by_pair.get(pair, []):
                if other.id not in flow_edge.alert_ids and other.id != a.id:
                    flow_edge.alert_ids.append(other.id)

        # 7) Incident edges (from capture.summary — correlated by suspicion engine)
        summary = capture.summary or {}
        for incident in (summary.get("incidents") or [])[:20]:
            src_ip = incident.get("source_ip")
            if not src_ip:
                continue
            # synthetic id namespaced by source IP: an incident node per source
            e = acc(incident_id(src_ip), host_id(src_ip), "GROUPS", provenance="correlated")
            e.observe(incident.get("first_seen") or 0.0, alert_id=None)
            e.count = max(e.count, int(incident.get("alert_count") or 0))
            for aid in (incident.get("alert_ids") or [])[: GraphCaps.MAX_ALERT_REFS]:
                if aid:
                    ae = acc(alert_id(str(aid)), incident_id(src_ip), "INCLUDES", provenance="correlated")
                    ae.observe(incident.get("first_seen") or 0.0, alert_id=str(aid))
            # keep last_seen bounded to incident window
            if incident.get("last_seen"):
                e.last_seen = max(e.last_seen or 0.0, float(incident["last_seen"]))

        # 8) Case edges (case → capture) — cases that include this capture
        case_rows = list(
            self.db.scalars(select(CaseModel).order_by(CaseModel.created_at.desc()).limit(500))
        )
        for c in case_rows:
            if cap_id in (c.capture_ids or []):
                e = acc(case_id(c.id), capture_id(cap_id), "INCLUDES", provenance="observed")
                created = c.created_at.timestamp() if c.created_at else 0.0
                e.observe(created)

        # 9) capture → node edges are implicit (hydration scoping), not stored.

        # explanations for suspicious FLOW edges
        for (src, dst, rel), e in edges.items():
            if rel == "FLOW" and e.alert_ids:
                key = (parse_node_id(src)[1], parse_node_id(dst)[1])
                related = alert_by_pair.get(key, [])
                e.explanation = self._explain(related or [])

        # cap provenance lists (bounded rows)
        for e in edges.values():
            e.flow_ids = e.flow_ids[: GraphCaps.MAX_FLOW_REFS]
            e.alert_ids = e.alert_ids[: GraphCaps.MAX_ALERT_REFS]
            e.packet_refs = e.packet_refs[: GraphCaps.MAX_PACKET_REFS]

        rows = []
        for (src, dst, rel), e in edges.items():
            rows.append(
                GraphEdgeModel(
                    id=f"{cap_id}:{src}->{dst}:{rel}",
                    capture_id=cap_id,
                    source_id=src,
                    target_id=dst,
                    relationship=rel,
                    provenance=e.provenance,
                    first_seen=e.first_seen or 0.0,
                    last_seen=e.last_seen or 0.0,
                    count=e.count,
                    packets=e.packets,
                    bytes=e.bytes,
                    protocol=e.protocol,
                    port=e.port,
                    flow_ids=e.flow_ids,
                    alert_ids=e.alert_ids,
                    packet_refs=e.packet_refs,
                    explanation=e.explanation,
                )
            )
        return rows


def ensure_materialized(db: Session, capture: CaptureModel) -> bool:
    """Idempotent lazy backfill: build + persist the graph if not present.

    Returns True when a build happened, False when edges already exist.
    Old captures (analyzed before Graph 2.0) get their evidence graph on
    first /api/graph/v2 request, transparently and exactly once.
    """
    existing = db.scalar(
        select(func.count())
        .select_from(GraphEdgeModel)
        .where(GraphEdgeModel.capture_id == capture.id)
    )
    if existing:
        return False
    rows = EvidenceGraphBuilder(db).build(capture)
    db.query(GraphEdgeModel).filter(GraphEdgeModel.capture_id == capture.id).delete()
    if rows:
        db.add_all(rows)
    db.commit()
    return True


# ---- Node hydration (query time, from source tables — no duplication) -------


def hydrate_node(
    capture_id: str, node_id: str, db: Session, referenced: bool = False
) -> dict | None:
    """Node metadata from the table that actually owns the data. None if unknown.

    ``referenced=True`` means the node id is known to appear in a graph edge
    (subgraph assembly) — host/domain fallbacks are allowed for nodes whose
    source row is absent (e.g. external IPs never profiled). With
    ``referenced=False`` (node-detail lookups) unknown nodes return None so
    the API can answer 404 — no invented nodes.
    """
    kind, key = parse_node_id(node_id)

    if kind == "host":
        host = db.scalar(
            select(HostModel).where(
                HostModel.capture_id == capture_id, HostModel.ip == key
            )
        )
        if host is None:
            if not referenced:
                return None
            # hosts referenced by flows but never profiled (e.g. pure external)
            return {
                "id": node_id,
                "kind": "host",
                "label": key,
                "internal": False,
                "alert_count": 0,
            }
        behavior = host.behavior_summary or {}
        return {
            "id": node_id,
            "kind": "host",
            "label": host.hostname or host.ip,
            "ip": host.ip,
            "internal": bool(host.is_internal),
            "role": host.role,
            "hostname": host.hostname,
            "bytes_sent": host.bytes_sent,
            "bytes_received": host.bytes_received,
            "first_seen": host.first_seen,
            "last_seen": host.last_seen,
            "alert_count": int(behavior.get("alert_count") or 0),
        }

    if kind == "domain":
        if not referenced:
            # unknown-domain lookups must 404: verify the name was actually
            # observed in this capture (DNS query, TLS SNI, or HTTP host)
            seen = (
                db.scalar(
                    select(func.count())
                    .select_from(DNSTransactionModel)
                    .where(
                        DNSTransactionModel.capture_id == capture_id,
                        DNSTransactionModel.query_name == key,
                    )
                )
                or 0
            ) or (
                db.scalar(
                    select(func.count())
                    .select_from(TLSSessionModel)
                    .where(
                        TLSSessionModel.capture_id == capture_id,
                        TLSSessionModel.sni == key,
                    )
                )
                or 0
            ) or (
                db.scalar(
                    select(func.count())
                    .select_from(HTTPTransactionModel)
                    .where(
                        HTTPTransactionModel.capture_id == capture_id,
                        HTTPTransactionModel.host == key,
                    )
                )
                or 0
            )
            if not seen:
                return None
        return {"id": node_id, "kind": "domain", "label": key}

    if kind == "service":
        ip, _, port = key.rpartition(":")
        return {"id": node_id, "kind": "service", "label": f"{ip}:{port}", "port": int(port)}

    if kind == "alert":
        a = db.get(AlertModel, key)
        if a is None or a.capture_id != capture_id:
            return None
        mitre = RULE_MITRE.get(a.rule_name)
        return {
            "id": node_id,
            "kind": "alert",
            "label": a.title,
            "rule_name": a.rule_name,
            "severity": a.severity,
            "score": a.score,
            "reasons": a.reasons or [],
            "explanation": a.explanation,
            "mitre": (
                {
                    "technique_id": mitre["technique_id"],
                    "technique": mitre["technique"],
                    "tactic": mitre["tactic"],
                    "source": mitre["source"],
                }
                if mitre
                else None
            ),
        }

    if kind == "incident":
        return {"id": node_id, "kind": "incident", "label": f"Incident on {key}"}

    if kind == "case":
        c = db.get(CaseModel, key)
        if c is None:
            return None
        return {"id": node_id, "kind": "case", "label": c.name, "status": c.status}

    if kind == "capture":
        c = db.get(CaptureModel, key)
        if c is None:
            return None
        return {
            "id": node_id,
            "kind": "capture",
            "label": c.filename,
            "filename": c.filename,
            "status": c.status,
            "packet_count": c.packet_count,
        }

    return None


# ---- Bounded graph algorithms (query-time inference, never persisted) -------


def build_adjacency(
    db: Session, capture_id: str, relationships: list[str] | None = None
) -> dict[str, list[tuple[str, GraphEdgeModel]]]:
    """Adjacency list over observed/correlated edges (excludes 'enriched')."""
    stmt = select(GraphEdgeModel).where(GraphEdgeModel.capture_id == capture_id)
    if relationships:
        stmt = stmt.where(GraphEdgeModel.relationship.in_(relationships))
    adj: dict[str, list[tuple[str, GraphEdgeModel]]] = defaultdict(list)
    for e in db.scalars(stmt):
        adj[e.source_id].append((e.target_id, e))
        # relationships are traversable in both directions for path finding
        adj[e.target_id].append((e.source_id, e))
    return adj


def find_attack_paths(
    db: Session,
    capture_id: str,
    source_node: str,
    target_node: str,
    max_depth: int = GraphCaps.MAX_PATH_DEPTH,
    max_paths: int = GraphCaps.MAX_PATHS,
    node_cap: int = GraphCaps.PATH_NODE_CAP,
) -> dict:
    """Bounded bidirectional-ish BFS path search over OBSERVED edges only.

    Every hop is an observed/correlated relationship; the PATH itself is an
    inference and is labeled as such in the response. Strictly bounded:
    depth ≤ max_depth, nodes visited ≤ node_cap, paths ≤ max_paths.
    """
    max_depth = min(max_depth, GraphCaps.MAX_PATH_DEPTH)
    max_paths = min(max_paths, GraphCaps.MAX_PATHS)
    node_cap = min(node_cap, GraphCaps.PATH_NODE_CAP)

    adj = build_adjacency(db, capture_id)
    if source_node not in adj or target_node not in adj:
        return {"paths": [], "visited": 0, "truncated": False, "reason": "unknown node"}

    # bounded BFS collecting simple paths up to max_depth
    visited_total = 0
    paths: list[list[str]] = []
    queue: deque[tuple[str, list[str]]] = deque([(source_node, [source_node])])
    seen_depth: dict[str, int] = {source_node: 0}
    truncated = False

    while queue:
        node, path = queue.popleft()
        visited_total += 1
        if visited_total > node_cap:
            truncated = True
            break
        if len(path) - 1 >= max_depth:
            continue
        for neighbor, _edge in adj.get(node, []):
            if neighbor in path:  # simple paths only
                continue
            new_path = path + [neighbor]
            if neighbor == target_node:
                paths.append(new_path)
                if len(paths) >= max_paths:
                    return {"paths": paths, "visited": visited_total, "truncated": truncated}
                continue
            # keep exploring (cheaper best-effort ordering: shorter depth first)
            if len(new_path) - 1 < max_depth:
                prev = seen_depth.get(neighbor)
                if (prev is None or len(new_path) - 1 < prev) and (
                    visited_total + len(queue) < node_cap * 2
                ):
                    seen_depth[neighbor] = len(new_path) - 1
                    queue.append((neighbor, new_path))

    return {"paths": paths[:max_paths], "visited": visited_total, "truncated": truncated}


def blast_radius(
    db: Session,
    capture_id: str,
    start_node: str,
    depth: int = 2,
    node_cap: int = GraphCaps.BLAST_NODE_CAP,
    hard_cap: int = GraphCaps.BLAST_HARD_NODE_CAP,
) -> dict:
    """BFS from a node, depth ≤ MAX_BLAST_DEPTH, node counts strictly capped.

    Returns the reachable subgraph (node ids per ring + edges) plus a
    summary of what an attacker starting at that node could touch —
    computed ONLY from observed relationships.
    """
    depth = min(depth, GraphCaps.MAX_BLAST_DEPTH)
    node_cap = min(node_cap, GraphCaps.BLAST_NODE_CAP)
    hard_cap = min(hard_cap, GraphCaps.BLAST_HARD_NODE_CAP)

    adj = build_adjacency(db, capture_id)
    if start_node not in adj:
        return {"nodes": [], "edges": [], "rings": {}, "truncated": False, "reason": "unknown node"}

    ring: dict[str, int] = {start_node: 0}
    rings: dict[int, list[str]] = defaultdict(list)
    edges_by_key: dict[tuple[str, str], GraphEdgeModel] = {}
    queue: deque[str] = deque([start_node])
    truncated = False

    while queue:
        node = queue.popleft()
        d = ring.get(node, 0)
        if d >= depth:
            continue
        for neighbor, edge in adj.get(node, []):
            if neighbor in ring:
                if ring[neighbor] > d + 1:
                    ring[neighbor] = d + 1
                edges_by_key.setdefault((edge.source_id, edge.target_id, edge.relationship), edge)
                continue
            if len(ring) >= hard_cap:
                truncated = True
                break
            ring[neighbor] = d + 1
            rings[d + 1].append(neighbor)
            edges_by_key.setdefault((edge.source_id, edge.target_id, edge.relationship), edge)
            if len(ring) < node_cap:
                queue.append(neighbor)

    # summary: what is reachable (alert-flagged nodes highlighted via alert ids on edges)
    alert_flagged: set[str] = set()
    for e in edges_by_key.values():
        if e.alert_ids:
            alert_flagged.add(e.source_id)
            alert_flagged.add(e.target_id)

    by_kind: dict[str, int] = defaultdict(int)
    for nid in ring:
        by_kind[parse_node_id(nid)[0]] += 1

    return {
        "start": start_node,
        "depth": depth,
        "nodes": sorted(ring.keys()),
        "rings": {str(k): v for k, v in rings.items()},
        "edges": [
            {
                "source": e.source_id,
                "target": e.target_id,
                "relationship": e.relationship,
                "provenance": e.provenance,
                "first_seen": e.first_seen,
                "last_seen": e.last_seen,
                "alert_ids": e.alert_ids,
            }
            for e in edges_by_key.values()
        ],
        "summary": {
            "reachable_nodes": len(ring),
            "by_kind": dict(by_kind),
            "alert_flagged": sorted(alert_flagged),
            "node_cap": node_cap,
            "hard_cap": hard_cap,
        },
        "truncated": truncated,
    }
