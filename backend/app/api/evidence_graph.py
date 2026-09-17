"""Evidence Graph 2.0 endpoints — versioned alongside the untouched /api/graph.

Every endpoint is scoped to one capture (capture_or_404), SQL-filtered, and
capped so the graph can never become an unbounded database operation.
Authorization model: same as the rest of PacketKage's API — single-tenant,
no per-user auth (documented assumption; all data is scoped by capture_id).
"""

from __future__ import annotations

from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.common import capture_or_404
from app.core.database import get_db
from app.db.orm import AlertModel, FlowModel
from app.repositories import GRAPH_PROVENANCE, GRAPH_RELATIONSHIPS, GraphEdgeRepository
from app.schemas.api import (
    GraphV2BlastOut,
    GraphV2Edge,
    GraphV2Node,
    GraphV2NodeOut,
    GraphV2Out,
    GraphV2Path,
    GraphV2PathsOut,
)
from app.services.evidence_graph import (
    GraphCaps,
    blast_radius,
    find_attack_paths,
    hydrate_node,
)

router = APIRouter(prefix="/api/graph/v2", tags=["evidence-graph"])


def _edge_out(e) -> GraphV2Edge:
    return GraphV2Edge(
        id=e.id,
        source=e.source_id,
        target=e.target_id,
        relationship=e.relationship,
        provenance=e.provenance,
        first_seen=e.first_seen,
        last_seen=e.last_seen,
        count=e.count,
        packets=e.packets,
        bytes=e.bytes,
        protocol=e.protocol,
        port=e.port,
        flow_ids=e.flow_ids or [],
        alert_ids=e.alert_ids or [],
        packet_refs=e.packet_refs or [],
        explanation=e.explanation,
    )


@router.get("", response_model=GraphV2Out)
def get_evidence_graph(
    capture_id: str,
    relationships: str | None = Query(default=None, description="Comma-separated relationship types"),
    provenance: str | None = Query(default=None, description="Comma-separated provenance classes"),
    after: float | None = Query(default=None, description="Window start (epoch s)"),
    before: float | None = Query(default=None, description="Window end (epoch s)"),
    min_alerts: int = Query(default=0, ge=0, description="Only alert-backed edges"),
    node_id: str | None = Query(default=None, description="Focus: incident edges of one node"),
    limit: int = Query(
        default=GraphCaps.DEFAULT_NODE_LIMIT,
        ge=1,
        le=GraphCaps.HARD_NODE_LIMIT,
        description="Node cap for the returned subgraph",
    ),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """Evidence-backed subgraph for a capture.

    Edges are filtered in SQL (relationship, provenance class, time-window
    overlap, alert presence, focus node) and the returned subgraph is capped
    at `limit` nodes — `truncated` flags when more data exists.

    Pagination: `offset` and `limit` define a window over the degree-ranked
    node list. For a focused `node_id`, the focus node and its neighbors are
    prioritized within the limit.

    Lazy backfill: for captures analyzed before Graph 2.0 (no edges exist),
    the graph is materialized on first request. This is idempotent and
    race-safe via transaction.
    """
    capture = capture_or_404(db, capture_id)
    repo = GraphEdgeRepository(db)

    # lazy one-time backfill for captures analyzed before Graph 2.0
    if repo.count_for_capture(capture_id) == 0 and capture.status == "completed":
        from app.services.evidence_graph import ensure_materialized

        ensure_materialized(db, capture)

    rel_list = None
    if relationships:
        rel_list = [r.strip().upper() for r in relationships.split(",") if r.strip()]
        bad = [r for r in rel_list if r not in GRAPH_RELATIONSHIPS]
        if bad:
            raise HTTPException(400, f"Unknown relationships {bad}; allowed: {sorted(GRAPH_RELATIONSHIPS)}")
    prov_list = None
    if provenance:
        prov_list = [p.strip().lower() for p in provenance.split(",") if p.strip()]
        bad = [p for p in prov_list if p not in GRAPH_PROVENANCE]
        if bad:
            raise HTTPException(400, f"Unknown provenance {bad}; allowed: {sorted(GRAPH_PROVENANCE)}")

    # Get all filtered edges (capped at 4000 by repository)
    edges = repo.list_for_capture(
        capture_id,
        relationships=rel_list,
        provenance=prov_list,
        after=after,
        before=before,
        with_alerts_only=min_alerts > 0,
        node_id=node_id,
    )
    total_edges = repo.count_for_capture(capture_id)

    # Build degree map from filtered edges
    degree: dict[str, int] = defaultdict(int)
    for e in edges:
        degree[e.source_id] += 1
        degree[e.target_id] += 1

    # Rank nodes by degree (highest first)
    ranked = sorted(degree.keys(), key=lambda n: -degree[n])

    # Determine kept nodes with proper pagination
    kept: set[str] = set()

    if node_id:
        # Focus mode: always include focus node + its neighbors, then fill
        # remaining slots with highest-degree nodes
        kept.add(node_id)
        for e in edges:
            if e.source_id == node_id:
                kept.add(e.target_id)
            elif e.target_id == node_id:
                kept.add(e.source_id)

        # Add highest-degree nodes up to limit (excluding already kept)
        remaining = limit - len(kept)
        if remaining > 0:
            for nid in ranked:
                if nid not in kept:
                    kept.add(nid)
                    remaining -= 1
                    if remaining <= 0:
                        break
    else:
        # Normal pagination: window over ranked nodes
        start = offset
        end = offset + limit
        for nid in ranked[start:end]:
            kept.add(nid)

    # Build kept edges
    kept_edges = [e for e in edges if e.source_id in kept and e.target_id in kept]

    # Truncated if there are more nodes than we returned
    truncated = len(ranked) > len(kept) + offset if not node_id else len(ranked) > limit

    nodes: list[GraphV2Node] = []
    for nid in sorted(kept):
        meta = hydrate_node(capture_id, nid, db, referenced=True)
        if meta is None:
            # node referenced by edges but its source row is gone (evidence
            # pruned) — keep the node visible with minimal info, not an error
            from app.services.evidence_graph import parse_node_id

            kind, key = parse_node_id(nid)
            meta = {"id": nid, "kind": kind, "label": key}
        nodes.append(GraphV2Node(**{k: v for k, v in meta.items() if k in GraphV2Node.model_fields}))

    stats = {
        "edge_count": len(kept_edges),
        "total_edges_in_capture": total_edges,
        "node_count": len(nodes),
        "total_nodes": len(ranked),
        "relationships": sorted({e.relationship for e in kept_edges}),
        "provenance_classes": sorted({e.provenance for e in kept_edges}),
        "alert_backed_edges": sum(1 for e in kept_edges if e.alert_ids),
    }
    return GraphV2Out(
        nodes=nodes,
        edges=[_edge_out(e) for e in kept_edges],
        stats=stats,
        truncated=truncated,
    )


@router.get("/node", response_model=GraphV2NodeOut)
def get_node_detail(
    capture_id: str,
    node_id: str = Query(description="Graph node id, e.g. host:192.168.1.42"),
    db: Session = Depends(get_db),
):
    """Node metadata + all incident edges (bounded) for the investigation panel."""
    capture_or_404(db, capture_id)
    repo = GraphEdgeRepository(db)

    meta = hydrate_node(capture_id, node_id, db)
    if meta is None:
        raise HTTPException(404, "Node not found in this capture")

    edges = repo.list_for_capture(capture_id, node_id=node_id, max_edges=200)
    incident = [_edge_out(e) for e in edges if e.source_id == node_id or e.target_id == node_id]
    stats = {
        "edge_count": len(incident),
        "alert_backed_edges": sum(1 for e in incident if e.alert_ids),
    }
    return GraphV2NodeOut(
        node=GraphV2Node(**{k: v for k, v in meta.items() if k in GraphV2Node.model_fields}),
        edges=incident,
        stats=stats,
    )


@router.get("/edge/{edge_id}", response_model=GraphV2Edge)
def get_edge_detail(edge_id: str, capture_id: str, db: Session = Depends(get_db)):
    """Full provenance for one relationship: the WHY + the evidence chain.

    Joins real flow and alert rows so every displayed claim traces to
    actual PacketKage data. Missing evidence (deleted flows/older captures)
    renders as empty references, never invented data.
    """
    capture_or_404(db, capture_id)
    repo = GraphEdgeRepository(db)
    e = repo.get(edge_id)
    if e is None or e.capture_id != capture_id:
        raise HTTPException(404, "Edge not found in this capture")

    out = _edge_out(e)

    if e.flow_ids:
        flow_rows = {f.id: f for f in db.query(FlowModel).filter(FlowModel.id.in_(e.flow_ids)).all()}
        out.flows = [
            {
                "id": fid,
                "source_ip": flow_rows[fid].source_ip,
                "destination_ip": flow_rows[fid].destination_ip,
                "destination_port": flow_rows[fid].destination_port,
                "transport_protocol": flow_rows[fid].transport_protocol,
                "application_protocol": flow_rows[fid].application_protocol,
                "packets": flow_rows[fid].packets,
                "bytes": flow_rows[fid].bytes,
                "first_seen": flow_rows[fid].first_seen,
                "last_seen": flow_rows[fid].last_seen,
            }
            for fid in e.flow_ids
            if fid in flow_rows
        ]
    if e.alert_ids:
        alert_rows = {a.id: a for a in db.query(AlertModel).filter(AlertModel.id.in_(e.alert_ids)).all()}
        from app.services.evidence_graph import RULE_MITRE

        out.alerts = [
            {
                "id": aid,
                "rule_name": alert_rows[aid].rule_name,
                "title": alert_rows[aid].title,
                "severity": alert_rows[aid].severity,
                "score": alert_rows[aid].score,
                "reasons": alert_rows[aid].reasons or [],
                "explanation": alert_rows[aid].explanation,
                "destination_port": alert_rows[aid].destination_port,
                "timestamp": alert_rows[aid].timestamp,
                "mitre": RULE_MITRE.get(alert_rows[aid].rule_name),
            }
            for aid in e.alert_ids
            if aid in alert_rows
        ]
    return out


@router.get("/paths", response_model=GraphV2PathsOut)
def get_attack_paths(
    capture_id: str,
    source: str = Query(description="Source node id, e.g. host:192.168.1.42"),
    target: str = Query(description="Target node id, e.g. host:10.0.0.5"),
    max_depth: int = Query(default=4, ge=1, le=GraphCaps.MAX_PATH_DEPTH),
    max_paths: int = Query(default=3, ge=1, le=GraphCaps.MAX_PATHS),
    db: Session = Depends(get_db),
):
    """Bounded attack-path extraction between two entities.

    Every hop is an OBSERVED relationship; the assembled PATH is an
    inference, labeled as such. Each hop includes its provenance.
    Bounded: depth ≤ 4, paths ≤ 3, visited nodes ≤ 200.
    """
    capture_or_404(db, capture_id)

    result = find_attack_paths(db, capture_id, source, target, max_depth, max_paths)
    paths = [GraphV2Path(nodes=p["nodes"], length=p["length"]) for p in result["paths"]]
    return GraphV2PathsOut(
        paths=paths,
        visited=result["visited"],
        truncated=result["truncated"],
        reason=result.get("reason"),
    )


@router.get("/blast", response_model=GraphV2BlastOut)
def get_blast_radius(
    capture_id: str,
    host: str = Query(description="Node id to start from, e.g. host:192.168.1.42"),
    depth: int = Query(default=2, ge=1, le=GraphCaps.MAX_BLAST_DEPTH),
    db: Session = Depends(get_db),
):
    """Blast-radius analysis from a node, strictly bounded.

    Depth ≤ 3, node cap 150 (hard 500). Reachability computed only
    from OBSERVED relationships — no correlated or enriched edges.
    """
    capture_or_404(db, capture_id)

    result = blast_radius(db, capture_id, host, depth)
    if result.get("reason") == "unknown node":
        raise HTTPException(404, f"Node {host} not found in this capture")
    return GraphV2BlastOut(**result)
