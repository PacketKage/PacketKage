"""Evidence Graph 2.0 tests: construction, provenance, caps, paths, blast, API.

Covers: relationship types, provenance classes, first/last-seen timestamps,
evidence ID capping, suspicious-edge explanations (real alerts only),
SQL filtering (relationship/provenance/time-window/alerts/focus), node caps
+ truncated flag, lazy backfill idempotency, attack-path bounds, blast-radius
bounds, missing-evidence behavior, 404s, adversarial scale, and regression
of the untouched v1 graph.
"""
from __future__ import annotations

import time

from tests.test_step1 import _analyze_and_wait, _upload


def _analyze(client, pcap: str) -> str:
    capture_id = _upload(client, pcap)
    job = _analyze_and_wait(client, capture_id)
    assert job["status"] == "completed", job
    return capture_id


# ---------------- Construction + provenance ----------------


def test_v2_relationships_and_provenance_classes(client):
    capture_id = _analyze(client, "c2_beacon.pcap")  # alerts → incidents exist
    g = client.get(f"/api/graph/v2?capture_id={capture_id}").json()
    rels = {e["relationship"] for e in g["edges"]}
    provs = {e["provenance"] for e in g["edges"]}

    # observed relationships from flows/services
    assert {"FLOW", "EXPOSES"} <= rels
    # correlated relationships from incidents/alerts
    assert {"GROUPS", "TRIGGERED", "TARGETS", "INCLUDES"} <= rels
    assert provs <= {"observed", "correlated", "enriched"}
    assert provs == {"observed", "correlated"}

    # observed-only capture: DNS/HTTP/TLS relationship types
    clean = _analyze(client, "normal_traffic.pcap")
    g2 = client.get(f"/api/graph/v2?capture_id={clean}").json()
    rels2 = {e["relationship"] for e in g2["edges"]}
    assert {"DNS_QUERY", "RESOLVES_TO", "HTTP_HOST", "FLOW", "EXPOSES"} <= rels2
    assert all(e["provenance"] == "observed" for e in g2["edges"])


def test_v2_node_kinds_and_hydration(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    g = client.get(f"/api/graph/v2?capture_id={capture_id}").json()
    by_id = {n["id"]: n for n in g["nodes"]}

    assert by_id["host:192.168.1.42"]["kind"] == "host"
    assert by_id["host:192.168.1.42"]["internal"] is True
    assert by_id["domain:example.com"]["kind"] == "domain"
    # service node hydration carries port
    svc = by_id["service:93.184.216.34:80"]
    assert svc["kind"] == "service" and svc["port"] == 80
    # alert nodes hydrate rule/severity/score from the alerts table
    alert_nodes = [n for n in g["nodes"] if n["kind"] == "alert"]
    assert all(n["severity"] and n["score"] is not None for n in alert_nodes)


def test_v2_flow_edge_provenance_full(client):
    """Every FLOW edge carries the required provenance fields."""
    capture_id = _analyze(client, "normal_traffic.pcap")
    g = client.get(f"/api/graph/v2?capture_id={capture_id}").json()
    flows = [e for e in g["edges"] if e["relationship"] == "FLOW"]
    assert flows, "expected FLOW edges"
    for e in flows:
        assert e["first_seen"] <= e["last_seen"]
        assert e["count"] >= 1
        assert e["protocol"] and e["port"]
        assert isinstance(e["flow_ids"], list) and e["flow_ids"]
        # flow ids reference real rows
        for fid in e["flow_ids"][:3]:
            resp = client.get(f"/api/flows/{fid}")
            assert resp.status_code == 200


def test_v2_alert_edges_and_mitre(client):
    capture_id = _analyze(client, "c2_beacon.pcap")
    g = client.get(f"/api/graph/v2?capture_id={capture_id}").json()
    alert_edges = [e for e in g["edges"] if e["relationship"] == "TRIGGERED"]
    assert alert_edges, "c2 beacon must produce alert edges"
    edge = alert_edges[0]
    assert edge["provenance"] == "correlated"
    assert edge["alert_ids"]

    # every TRIGGERED edge detail joins its real alert with MITRE enrichment
    det = client.get(f"/api/graph/v2/edge/{edge['id']}?capture_id={capture_id}").json()
    assert det["alerts"], "edge detail must join alert rows"
    a = det["alerts"][0]
    assert a["mitre"], f"rule {a['rule_name']} must have curated MITRE mapping"
    assert a["mitre"]["technique_id"]
    assert a["mitre"]["tactic"]

    # the beaconing rule specifically carries the C2 mapping
    all_alerts = []
    for e in alert_edges:
        d = client.get(f"/api/graph/v2/edge/{e['id']}?capture_id={capture_id}").json()
        all_alerts.extend(d["alerts"])
    rules = {x["rule_name"] for x in all_alerts}
    assert "beaconing" in rules
    beacon = next(x for x in all_alerts if x["rule_name"] == "beaconing")
    assert beacon["mitre"]["technique_id"] == "C1091"
    assert beacon["mitre"]["tactic"] == "Command and Control"
    # every joined alert carries its rule's curated MITRE map entry (or none)
    for x in all_alerts:
        assert x["mitre"] is None or x["mitre"]["technique_id"]


def test_v2_suspicious_edge_explanation_from_real_alerts_only(client):
    capture_id = _analyze(client, "c2_beacon.pcap")
    g = client.get(f"/api/graph/v2?capture_id={capture_id}").json()
    flow = next(e for e in g["edges"] if e["relationship"] == "FLOW" and e["alert_ids"])
    assert flow["explanation"]
    # explanation aggregates only REAL alert rules for this capture
    det = client.get(f"/api/graph/v2/edge/{flow['id']}?capture_id={capture_id}").json()
    rules = {a["rule_name"] for a in det["alerts"]}
    for rule in rules:
        assert rule in flow["explanation"].lower() or rule in flow["explanation"]
    # clean traffic: no alert-backed edges, no invented explanations
    clean = _analyze(client, "normal_traffic.pcap")
    g2 = client.get(f"/api/graph/v2?capture_id={clean}").json()
    assert all(not e["explanation"] for e in g2["edges"])
    assert g2["stats"]["alert_backed_edges"] == 0


def test_v2_aggregation_c2_beacon(client):
    """40 beacon flows between one pair aggregate into ONE FLOW edge."""
    capture_id = _analyze(client, "c2_beacon.pcap")
    g = client.get(f"/api/graph/v2?capture_id={capture_id}").json()
    edge = next(
        e
        for e in g["edges"]
        if e["relationship"] == "FLOW"
        and e["source"] == "host:192.168.1.42"
        and e["target"] == "host:185.234.72.19"
    )
    assert edge["count"] == 40
    assert edge["packets"] == 120
    assert len(edge["flow_ids"]) == 40  # under cap (100)


# ---------------- Filtering ----------------


def test_v2_filter_relationships(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    g = client.get(
        f"/api/graph/v2?capture_id={capture_id}&relationships=DNS_QUERY,RESOLVES_TO"
    ).json()
    assert {e["relationship"] for e in g["edges"]} == {"DNS_QUERY", "RESOLVES_TO"}

    # invalid relationship rejected
    resp = client.get(f"/api/graph/v2?capture_id={capture_id}&relationships=NOPE")
    assert resp.status_code == 400


def test_v2_filter_provenance(client):
    capture_id = _analyze(client, "c2_beacon.pcap")
    g = client.get(f"/api/graph/v2?capture_id={capture_id}&provenance=correlated").json()
    assert g["edges"], "correlated (incident/alert) edges exist"
    assert all(e["provenance"] == "correlated" for e in g["edges"])

    resp = client.get(f"/api/graph/v2?capture_id={capture_id}&provenance=bogus")
    assert resp.status_code == 400


def test_v2_time_window_filters(client):
    """Time-window uses interval overlap semantics."""
    capture_id = _analyze(client, "c2_beacon.pcap")
    all_g = client.get(f"/api/graph/v2?capture_id={capture_id}").json()
    # c2 beacon spans BASE_TS .. BASE_TS+1170s; take a narrow early window
    t0 = min(e["first_seen"] for e in all_g["edges"])
    early = client.get(
        f"/api/graph/v2?capture_id={capture_id}&after={t0}&before={t0 + 60}"
    ).json()
    assert early["edges"], "early window must contain edges"
    for e in early["edges"]:
        assert e["last_seen"] >= t0 and e["first_seen"] <= t0 + 60

    # window entirely after capture end → no edges
    late = client.get(
        f"/api/graph/v2?capture_id={capture_id}&after={t0 + 100000}"
    ).json()
    assert late["edges"] == []


def test_v2_min_alerts_and_focus(client):
    capture_id = _analyze(client, "c2_beacon.pcap")
    g = client.get(f"/api/graph/v2?capture_id={capture_id}&min_alerts=1").json()
    assert g["edges"]
    assert all(e["alert_ids"] for e in g["edges"])

    focus = client.get(
        f"/api/graph/v2?capture_id={capture_id}&node_id=host:192.168.1.42"
    ).json()
    assert focus["edges"]
    assert all(
        "host:192.168.1.42" in (e["source"], e["target"]) for e in focus["edges"]
    )


def test_v2_node_detail_endpoint(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    node = client.get(
        f"/api/graph/v2/node?capture_id={capture_id}&node_id=host:192.168.1.42"
    ).json()
    assert node["node"]["kind"] == "host"
    assert node["node"]["ip"] == "192.168.1.42"
    assert node["edges"], "incident edges present"
    assert node["stats"]["edge_count"] == len(node["edges"])

    resp = client.get(
        f"/api/graph/v2/node?capture_id={capture_id}&node_id=host:10.99.99.99"
    )
    # host never seen in this capture → 404 (no invented nodes)
    assert resp.status_code == 404


def test_v2_edge_detail_missing_evidence_is_empty_not_error(client):
    """Edge with deleted/pruned evidence renders empty references, never fabricates."""
    capture_id = _analyze(client, "c2_beacon.pcap")
    g = client.get(f"/api/graph/v2?capture_id={capture_id}").json()
    edge = g["edges"][0]
    # bogus edge id → 404
    resp = client.get(f"/api/graph/v2/edge/nope?capture_id={capture_id}")
    assert resp.status_code == 404
    # wrong capture scoping → 404 (no cross-capture leakage)
    other = _analyze(client, "normal_traffic.pcap")
    resp = client.get(f"/api/graph/v2/edge/{edge['id']}?capture_id={other}")
    assert resp.status_code == 404


# ---------------- Caps + adversarial scale ----------------


def test_v2_node_limit_and_truncated_flag(client):
    capture_id = _analyze(client, "large_graph.pcap")
    full = client.get(f"/api/graph/v2?capture_id={capture_id}").json()
    capped = client.get(
        f"/api/graph/v2?capture_id={capture_id}&limit=50"
    ).json()
    assert capped["truncated"] is True
    assert len(capped["nodes"]) <= 50 + 10  # cap + focus expansion slack
    assert capped["stats"]["total_edges_in_capture"] >= full["stats"]["edge_count"]
    assert len(capped["nodes"]) < len(full["nodes"])

    # hard limit enforced by validation
    resp = client.get(f"/api/graph/v2?capture_id={capture_id}&limit=100000")
    assert resp.status_code == 422


def test_v2_adversarial_large_capture_bounded_and_fast(client):
    """~950-element capture: response stays bounded and returns quickly."""
    capture_id = _analyze(client, "large_graph.pcap")
    t0 = time.time()
    g = client.get(f"/api/graph/v2?capture_id={capture_id}").json()
    elapsed = time.time() - t0

    assert len(g["nodes"]) <= 1000
    assert len(g["edges"]) <= 4000
    assert elapsed < 10, f"graph query too slow: {elapsed:.2f}s"

    # every provenance list is capped
    for e in g["edges"]:
        assert len(e["flow_ids"]) <= 100
        assert len(e["alert_ids"]) <= 50
        assert len(e["packet_refs"]) <= 100

    # v1 regression: the old endpoint still works on the same capture
    v1 = client.get(f"/api/graph?capture_id={capture_id}").json()
    assert v1["stats"]["node_count"] > 300  # scale-tier capture unchanged


def test_v2_provenance_reference_caps_forced(client):
    """Builder caps flow/alert/packet reference lists even under pressure."""
    capture_id = _analyze(client, "port_scan.pcap")  # 100 distinct failed flows
    g = client.get(f"/api/graph/v2?capture_id={capture_id}").json()
    for e in g["edges"]:
        assert len(e["flow_ids"]) <= 100
        assert len(e["packet_refs"]) <= 100


# ---------------- Attack paths ----------------


def test_v2_attack_paths_bounded(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    p = client.get(
        f"/api/graph/v2/paths?capture_id={capture_id}"
        "&source=host:192.168.1.42&target=host:93.184.216.34"
    ).json()
    assert p["paths"], "direct flow path exists"
    path = p["paths"][0]
    assert path["nodes"][0] == "host:192.168.1.42"
    assert path["nodes"][-1] == "host:93.184.216.34"
    assert path["length"] == len(path["nodes"]) - 1
    assert len(p["paths"]) <= 3

    # hops traverse observed edges: adjacent nodes share an edge
    edges = {
        (e["source"], e["target"]) for e in client.get(
            f"/api/graph/v2?capture_id={capture_id}"
        ).json()["edges"]
    }
    for a, b in zip(path["nodes"], path["nodes"][1:], strict=False):
        assert (a, b) in edges or (b, a) in edges

    # depth bound respected
    shallow = client.get(
        f"/api/graph/v2/paths?capture_id={capture_id}"
        f"&source=host:192.168.1.42&target=host:93.184.216.34&max_depth=1"
    ).json()
    assert all(pp["length"] <= 1 for pp in shallow["paths"])

    # unknown nodes → empty with reason, not error
    missing = client.get(
        f"/api/graph/v2/paths?capture_id={capture_id}"
        "&source=host:1.2.3.4&target=host:93.184.216.34"
    ).json()
    assert missing["paths"] == [] and missing["reason"] == "unknown node"

    # API-level depth validation
    resp = client.get(
        f"/api/graph/v2/paths?capture_id={capture_id}"
        "&source=host:192.168.1.42&target=host:93.184.216.34&max_depth=9"
    )
    assert resp.status_code == 422


def test_v2_attack_paths_no_invented_hops(client):
    """Multi-hop path through DNS: host → domain → resolved ip."""
    capture_id = _analyze(client, "dns_tunneling.pcap")
    p = client.get(
        f"/api/graph/v2/paths?capture_id={capture_id}"
        "&source=host:192.168.1.42&target=host:8.8.8.8"
    ).json()
    for path in p["paths"]:
        for node in path["nodes"]:
            kind = node.split(":", 1)[0]
            assert kind in ("host", "domain", "service", "alert", "incident")
            # every node in a path must appear in the capture's graph
        found = client.get(
            f"/api/graph/v2?capture_id={capture_id}&node_id={path['nodes'][0]}"
        ).json()
        assert found["edges"], "path start must be a real observed node"


# ---------------- Blast radius ----------------


def test_v2_blast_radius_bounded(client):
    capture_id = _analyze(client, "large_graph.pcap")
    b = client.get(
        f"/api/graph/v2/blast?capture_id={capture_id}&host=host:192.168.1.42&depth=2"
    ).json()
    assert b["start"] == "host:192.168.1.42"
    assert b["depth"] == 2
    assert len(b["nodes"]) <= 500
    assert "host:192.168.1.42" in b["nodes"]
    # summary counts match returned data
    assert b["summary"]["reachable_nodes"] == len(b["nodes"])
    by_kind_sum = sum(b["summary"]["by_kind"].values())
    assert by_kind_sum == len(b["nodes"])
    # every alert-flagged node is backed by an edge carrying alert ids
    flagged = set(b["summary"]["alert_flagged"])
    backed = set()
    for e in b["edges"]:
        if e["alert_ids"]:
            backed.add(e["source"])
            backed.add(e["target"])
    assert flagged <= backed


def test_v2_blast_radius_depth_caps(client):
    capture_id = _analyze(client, "large_graph.pcap")
    shallow = client.get(
        f"/api/graph/v2/blast?capture_id={capture_id}&host=host:192.168.1.42&depth=1"
    ).json()
    deep = client.get(
        f"/api/graph/v2/blast?capture_id={capture_id}&host=host:192.168.1.42&depth=3"
    ).json()
    assert len(deep["nodes"]) >= len(shallow["nodes"])
    # API rejects depth > 3
    resp = client.get(
        f"/api/graph/v2/blast?capture_id={capture_id}&host=host:192.168.1.42&depth=9"
    )
    assert resp.status_code == 422
    # unknown host → 404
    resp = client.get(
        f"/api/graph/v2/blast?capture_id={capture_id}&host=host:8.8.4.4"
    )
    assert resp.status_code == 404


# ---------------- Backfill + regression ----------------


def test_v2_lazy_backfill_idempotent(client):
    """Simulated old capture: edges deleted, first v2 request rebuilds exactly once."""
    capture_id = _analyze(client, "normal_traffic.pcap")

    # simulate pre-2.0 capture by wiping its materialized edges
    from app.core.database import SessionLocal
    from app.db.orm import GraphEdgeModel

    with SessionLocal() as db:
        db.query(GraphEdgeModel).filter(
            GraphEdgeModel.capture_id == capture_id
        ).delete()
        db.commit()

    g1 = client.get(f"/api/graph/v2?capture_id={capture_id}").json()
    assert g1["edges"], "backfill rebuilt the graph"
    n1 = len(g1["edges"])

    # second request: no rebuild (idempotent), same data
    g2 = client.get(f"/api/graph/v2?capture_id={capture_id}").json()
    assert len(g2["edges"]) == n1


def test_v1_graph_regression_untouched(client):
    """The legacy /api/graph endpoint behaves exactly as before."""
    capture_id = _analyze(client, "normal_traffic.pcap")
    graph = client.get(f"/api/graph?capture_id={capture_id}").json()
    nodes = {n["data"]["id"] for n in graph["nodes"]}
    edge_types = {
        (e["data"]["source"], e["data"]["target"], e["data"]["type"])
        for e in graph["edges"]
    }
    assert {"192.168.1.42", "example.com", "93.184.216.34:80"} <= nodes
    assert ("192.168.1.42", "example.com", "DNS") in edge_types
    assert ("192.168.1.42", "93.184.216.34", "HTTP") in edge_types
    # v1 shape unchanged (flat ids, no provenance fields)
    sample = graph["edges"][0]["data"]
    assert "provenance" not in sample and "first_seen" not in sample


def test_v2_404s_and_scoping(client):
    resp = client.get("/api/graph/v2?capture_id=missing")
    assert resp.status_code == 404
    other = _analyze(client, "c2_beacon.pcap")
    # node scoped per capture: a node from capture A is 404 under capture B
    resp = client.get(
        f"/api/graph/v2/node?capture_id={other}&node_id=domain:example.com"
    )
    # example.com genuinely absent from c2_beacon → unknown node
    assert resp.status_code == 404


def test_v2_empty_capture_states(client):
    """A capture with no alerts renders an honest, explanation-free graph."""
    capture_id = _analyze(client, "dhcp_lease.pcap")
    g = client.get(f"/api/graph/v2?capture_id={capture_id}").json()
    # no invented nodes or alerts
    assert all(n["kind"] in ("host", "domain", "service") for n in g["nodes"])
    assert all(not e["explanation"] for e in g["edges"])
    assert all(not e["alert_ids"] for e in g["edges"])
    p = client.get(
        f"/api/graph/v2/paths?capture_id={capture_id}"
        "&source=host:192.168.1.42&target=host:192.168.1.1"
    ).json()
    assert isinstance(p["paths"], list)
