"""Step 5 tests: timeline, graph, replay."""

from __future__ import annotations

from tests.test_step1 import _analyze_and_wait, _upload


def _analyze(client, pcap: str) -> str:
    capture_id = _upload(client, pcap)
    job = _analyze_and_wait(client, capture_id)
    assert job["status"] == "completed", job
    return capture_id


# ---------------- Timeline ----------------


def test_timeline_built_normal(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    events = client.get(f"/api/timeline?capture_id={capture_id}&limit=1000").json()["items"]
    types = [e["event_type"] for e in events]
    # chronological order
    ts = [e["timestamp"] for e in events]
    assert ts == sorted(ts)
    assert types.count("dns_query") == 3
    assert types.count("dns_response") == 3
    assert types.count("http_request") == 2
    assert types.count("tls_handshake") == 1
    assert types.count("tcp_connect") == 3
    assert types.count("udp_session") == 3
    assert types.count("alert") == 0  # clean traffic

    # event contents
    dns_q = next(e for e in events if e["event_type"] == "dns_query")
    assert dns_q["source_ip"] == "192.168.1.42"
    assert dns_q["domain"] == "example.com"
    http = next(e for e in events if e["event_type"] == "http_request")
    assert "GET" in http["label"] and "example.com" in http["label"]
    assert http["detail"]["status"] == 200 or http["detail"]["status"] == 404


def test_timeline_alerts_and_failures(client):
    capture_id = _analyze(client, "c2_beacon.pcap")
    events = client.get(f"/api/timeline?capture_id={capture_id}&limit=1000").json()["items"]
    types = [e["event_type"] for e in events]
    assert types.count("tcp_connect") == 40
    assert types.count("alert") == 3
    alert_events = [e for e in events if e["event_type"] == "alert"]
    assert all(e["severity"] in ("high", "critical") for e in alert_events)
    assert all(e["related_alert_id"] for e in alert_events)
    # beacon connections carry flow references
    conn = next(e for e in events if e["event_type"] == "tcp_connect")
    assert conn["related_flow_id"]
    assert conn["destination_port"] == 4444


def test_timeline_filters_host(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    # filter by source ip
    events = client.get(f"/api/timeline?capture_id={capture_id}&host=192.168.1.42&limit=1000").json()["items"]
    assert all((e["source_ip"] == "192.168.1.42" or e["destination_ip"] == "192.168.1.42") for e in events)
    # filter by domain
    events = client.get(f"/api/timeline?capture_id={capture_id}&host=github&limit=1000").json()["items"]
    assert all(e["domain"] and "github" in e["domain"].lower() for e in events)
    assert len(events) >= 2  # query + response


def test_timeline_filters_protocol_type_severity_time(client):
    capture_id = _analyze(client, "c2_beacon.pcap")
    # protocol filter
    events = client.get(f"/api/timeline?capture_id={capture_id}&protocol=tcp&limit=1000").json()["items"]
    assert all("TCP" in (e["protocol"] or "").upper() for e in events if e["protocol"])
    # event type filter
    events = client.get(f"/api/timeline?capture_id={capture_id}&event_type=alert&limit=1000").json()["items"]
    assert all(e["event_type"] == "alert" for e in events)
    # severity filter
    events = client.get(f"/api/timeline?capture_id={capture_id}&severity=critical&limit=1000").json()["items"]
    assert all(e["severity"] == "critical" for e in events)
    # time window: first 60s covers first two beacons
    all_events = client.get(f"/api/timeline?capture_id={capture_id}&limit=1000").json()["items"]
    t0 = all_events[0]["timestamp"]
    events = client.get(
        f"/api/timeline?capture_id={capture_id}&after={t0}&before={t0 + 60}&limit=1000"
    ).json()["items"]
    assert all(t0 <= e["timestamp"] <= t0 + 60 for e in events)
    assert len(events) < len(all_events)


def test_timeline_failed_flows_marked(client):
    capture_id = _analyze(client, "port_scan.pcap")
    events = client.get(f"/api/timeline?capture_id={capture_id}&limit=1000").json()["items"]
    failed = [e for e in events if e["event_type"] == "flow_failed"]
    assert len(failed) == 100
    assert all(e["severity"] == "medium" for e in failed)


# ---------------- Graph ----------------


def test_graph_shape_normal(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    graph = client.get(f"/api/graph?capture_id={capture_id}").json()

    nodes = {n["data"]["id"]: n["data"] for n in graph["nodes"]}
    edges = graph["edges"]

    # hosts
    assert {"192.168.1.42", "192.168.1.1", "93.184.216.34"} <= set(nodes)
    # domains
    assert {"example.com", "github.com", "wikipedia.org"} <= set(nodes)
    # services on web server + dns server
    assert "93.184.216.34:80" in nodes
    assert "192.168.1.1:53" in nodes

    # roles carried
    assert nodes["93.184.216.34"]["role"] == "Web server"
    assert nodes["192.168.1.1"]["role"] == "DNS server"
    assert nodes["192.168.1.42"]["internal"] is True

    # edge types
    edge_types = {(e["data"]["source"], e["data"]["target"], e["data"]["type"]) for e in edges}
    assert ("192.168.1.42", "example.com", "DNS") in edge_types
    assert ("example.com", "93.184.216.34", "RESOLVES_TO") in edge_types
    assert ("192.168.1.42", "93.184.216.34", "HTTP") in edge_types
    assert ("192.168.1.42", "wikipedia.org", "TLS") in edge_types
    # DNS server exposes :53
    assert ("192.168.1.1", "192.168.1.1:53", "EXPOSES") in edge_types

    # stats consistent
    s = graph["stats"]
    assert s["node_count"] == len(graph["nodes"])
    assert s["edge_count"] == len(edges)
    assert s["host_count"] >= 3
    assert s["domain_count"] == 3


def test_graph_edge_aggregation(client):
    capture_id = _analyze(client, "c2_beacon.pcap")
    graph = client.get(f"/api/graph?capture_id={capture_id}").json()
    # 40 beacon flows between the same pair aggregate into ONE edge with count=40
    edge = next(
        e for e in graph["edges"] if e["data"]["source"] == "192.168.1.42" and e["data"]["type"] != "EXPOSES"
    )
    assert edge["data"]["count"] == 40
    assert edge["data"]["packets"] == 120  # 40 * 3
    assert len(edge["data"]["flow_ids"]) == 40


def test_graph_not_found(client):
    resp = client.get("/api/graph?capture_id=missing")
    assert resp.status_code == 404


# ---------------- Replay ----------------


def test_replay_stream(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    events = client.get(f"/api/replay?capture_id={capture_id}").json()
    assert len(events) == 15  # 3 dns_q + 3 dns_r + 3 udp + 3 tcp + 2 http + 1 tls
    ts = [e["timestamp"] for e in events]
    assert ts == sorted(ts)

    # after-cursor returns strictly later events
    mid = events[5]["timestamp"]
    later = client.get(f"/api/replay?capture_id={capture_id}&after={mid}").json()
    assert all(e["timestamp"] > mid for e in later)
    expected = sum(1 for e in events if e["timestamp"] > mid)
    assert len(later) == expected


def test_replay_incident_story(client):
    """The c2 incident should replay as: normal-ish connections then beacon alerts."""
    capture_id = _analyze(client, "dns_tunneling.pcap")
    events = client.get(f"/api/replay?capture_id={capture_id}").json()
    # interleaved dns queries and NXDOMAIN responses
    types = [e["event_type"] for e in events]
    assert types.count("dns_query") == 64
    assert types.count("dns_response") == 64
    # alerts present near the end (alert ts anchored to first related flow)
    assert types.count("alert") == 2


def test_timeline_summary_in_capture(client):
    capture_id = _analyze(client, "c2_beacon.pcap")
    capture = client.get(f"/api/captures/{capture_id}").json()
    ts = capture["summary"]["timeline_summary"]
    assert ts["total_events"] > 0
    assert ts["by_type"]["tcp_connect"] == 40
    assert ts["by_type"]["alert"] == 3
