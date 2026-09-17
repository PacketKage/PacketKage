"""Step 2 tests: flow reconstruction — aggregation, TCP states, evidence drill-down."""

from __future__ import annotations

from tests.test_step1 import _analyze_and_wait, _upload


def _flows_for(client, pcap_name: str) -> tuple[str, list]:
    capture_id = _upload(client, pcap_name)
    _analyze_and_wait(client, capture_id)
    flows: list = []
    offset = 0
    # paginate through the full flow set
    while True:
        resp = client.get(f"/api/flows?capture_id={capture_id}&limit=500&offset={offset}")
        assert resp.status_code == 200, resp.text
        page = resp.json()
        flows.extend(page["items"])
        offset += page["limit"]
        if offset >= page["total"]:
            break
    return capture_id, flows


def test_flows_bidirectional_aggregation(client):
    """HTTP req+resp and DNS q+r must each aggregate into one flow with fwd/rev split."""
    capture_id, flows = _flows_for(client, "normal_traffic.pcap")
    tcp_flows = [f for f in flows if f["transport_protocol"] == "TCP"]
    assert len(tcp_flows) == 3  # 2 HTTP + 1 TLS
    for f in tcp_flows:
        assert f["source_ip"] == "192.168.1.42"
        assert f["destination_ip"] == "93.184.216.34"
        assert f["packets"] == 2  # request + response / clienthello + serverhello
        assert f["packets_forward"] == 1
        assert f["packets_reverse"] == 1
        assert f["bytes"] == sum([f["bytes_forward"], f["bytes_reverse"]])
        assert f["direction"] == "outbound"
    # UDP DNS flows: 3 (one per domain, distinct source ports)
    udp_flows = [f for f in flows if f["transport_protocol"] == "UDP"]
    assert len(udp_flows) == 3
    assert all(f["application_protocol"] == "DNS" for f in udp_flows)
    assert all(f["packets"] == 2 for f in udp_flows)  # query + response


def test_flow_direction_internal(client):
    """Both-private endpoints => internal direction."""
    capture_id, flows = _flows_for(client, "port_scan.pcap")
    assert all(f["direction"] == "internal" for f in flows)


def test_port_scan_many_failed_flows(client):
    """A SYN scan produces many half_open/failed flows to distinct ports."""
    capture_id, flows = _flows_for(client, "port_scan.pcap")
    assert len(flows) == 100  # one flow per scanned port
    assert all(f["tcp_state"] == "half_open" for f in flows)
    assert all(f["failed"] for f in flows)
    assert all(f["packets"] == 1 for f in flows)
    dst_ports = {f["destination_port"] for f in flows}
    assert len(dst_ports) == 100


def test_tcp_problems_retransmissions_and_resets(client):
    """Detect data retransmission, SYN retransmission, resets, and failed connections."""
    capture_id, flows = _flows_for(client, "tcp_problems.pcap")

    by_dport = {}
    for f in flows:
        by_dport.setdefault(f["destination_port"], []).append(f)

    # flow to :80 (established w/ data retransmission)
    f80 = by_dport[80][0]
    assert f80["tcp_state"] == "established"
    assert f80["retransmissions"] >= 1  # the DATA-1 retransmit
    assert f80["resets"] == 0
    assert not f80["failed"]

    # SYN-retransmission flow (single flow, syn_retransmissions counted)
    assert len(by_dport[80]) == 2
    f80b = by_dport[80][1]
    assert f80b["syn_retransmissions"] == 1
    assert f80b["failed"] is False  # eventually succeeded

    # reset flow
    f8080 = by_dport[8080][0]
    assert f8080["tcp_state"] == "reset"
    assert f8080["resets"] == 1

    # 5 failed flows (SYN, no SYN-ACK) to port 81
    assert len(by_dport[81]) == 5
    assert all(f["failed"] and f["tcp_state"] == "half_open" for f in by_dport[81])


def test_dns_tunneling_udp_flows(client):
    """DNS tunneling groups into 8 UDP flows of 16 packets each."""
    capture_id, flows = _flows_for(client, "dns_tunneling.pcap")
    assert all(f["transport_protocol"] == "UDP" for f in flows)
    assert len(flows) == 8
    assert all(f["application_protocol"] == "DNS" for f in flows)
    # every flow: 8 queries + 8 responses
    assert all(f["packets"] == 16 for f in flows)


def test_c2_beacon_multiple_flows(client):
    """Beacon cycles use a unique source port each -> 40 flows to same destination."""
    capture_id, flows = _flows_for(client, "c2_beacon.pcap")
    assert len(flows) == 40
    assert all(f["destination_ip"] == "185.234.72.19" for f in flows)
    assert all(f["destination_port"] == 4444 for f in flows)
    assert all(f["tcp_state"] == "established" for f in flows)
    assert all(f["packets"] == 3 for f in flows)  # SYN, SYN-ACK, beacon payload
    assert all(f["retransmissions"] == 0 for f in flows)


def test_flow_detail_packet_evidence(client):
    """Flow detail must include the related packets (Flow → evidence drill-down)."""
    capture_id, flows = _flows_for(client, "c2_beacon.pcap")
    flow = flows[0]
    resp = client.get(f"/api/flows/{flow['id']}")
    assert resp.status_code == 200
    detail = resp.json()
    assert detail["id"] == flow["id"]
    assert detail["packet_evidence"]
    assert len(detail["packet_evidence"]) == flow["packets"]
    # evidence is chronological and references the right conversation
    ts = [p["timestamp"] for p in detail["packet_evidence"]]
    assert ts == sorted(ts)
    assert all(
        p["source_ip"] in ("192.168.1.42", "185.234.72.19")
        and p["destination_ip"] in ("192.168.1.42", "185.234.72.19")
        for p in detail["packet_evidence"]
    )
    # first packet must be the SYN
    assert "SYN" in detail["packet_evidence"][0]["flags"]


def test_flow_summary_in_capture(client):
    """Capture summary carries flow stats for the dashboard."""
    capture_id, flows = _flows_for(client, "tcp_problems.pcap")
    capture = client.get(f"/api/captures/{capture_id}").json()
    fs = capture["summary"]["flow_summary"]
    assert fs["flow_count"] == len(flows)
    assert fs["failed_flows"] == 6  # 5 unanswered + 1 reset (never saw SYN-ACK)
    assert fs["reset_flows"] == 1
    assert fs["retransmitting_flows"] >= 1
    assert fs["tcp_states"]["established"] == 2
    assert fs["tcp_states"]["reset"] == 1
    assert fs["tcp_states"]["half_open"] == 5
    assert fs["direction_counts"]["outbound"] == len(flows)


def test_flow_filters(client):
    """Transport + direction filters narrow the flow list (server-side, paginated)."""
    capture_id, _ = _flows_for(client, "normal_traffic.pcap")
    tcp_only = client.get(f"/api/flows?capture_id={capture_id}&transport=TCP").json()
    assert tcp_only["total"] == 3
    assert all(f["transport_protocol"] == "TCP" for f in tcp_only["items"])
    outbound = client.get(f"/api/flows?capture_id={capture_id}&direction=outbound").json()
    assert outbound["total"] > 0
    assert all(f["direction"] == "outbound" for f in outbound["items"])


def test_flow_pagination(client):
    """limit/offset paging returns correct slices + accurate totals."""
    capture_id, _ = _flows_for(client, "port_scan.pcap")
    p1 = client.get(f"/api/flows?capture_id={capture_id}&limit=10&offset=0").json()
    p2 = client.get(f"/api/flows?capture_id={capture_id}&limit=10&offset=10").json()
    assert p1["total"] == 100
    assert len(p1["items"]) == 10
    assert len(p2["items"]) == 10
    assert p1["items"][0]["id"] != p2["items"][0]["id"]


def test_flow_not_found(client):
    resp = client.get("/api/flows/nonexistent")
    assert resp.status_code == 404


def test_flows_require_capture(client):
    resp = client.get("/api/flows?capture_id=missing")
    assert resp.status_code == 404


def test_flow_builder_direct_unit():
    """Unit-level: FlowBuilder canonicalization and direction logic."""
    from app.core.models import NormalizedPacket
    from app.services.flow_builder import FlowBuilder, is_private_ip

    assert is_private_ip("192.168.1.42")
    assert is_private_ip("10.0.0.1")
    assert not is_private_ip("8.8.8.8")

    # packet in one direction then the reverse must aggregate into one flow
    fwd = NormalizedPacket(
        timestamp=1.0,
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        transport="TCP",
        source_port=1234,
        destination_port=80,
        flags=["SYN"],
        packet_reference=0,
    )
    rev = NormalizedPacket(
        timestamp=1.1,
        source_ip="10.0.0.2",
        destination_ip="10.0.0.1",
        transport="TCP",
        source_port=80,
        destination_port=1234,
        flags=["SYN", "ACK"],
        packet_reference=1,
    )
    builder = FlowBuilder()
    builder.add_packet(fwd)
    builder.add_packet(rev)
    flows = builder.build()
    assert len(flows) == 1
    assert flows[0]["packets"] == 2
    assert flows[0]["packets_forward"] == 1
    assert flows[0]["packets_reverse"] == 1
    assert flows[0]["tcp_state"] == "established"
    assert flows[0]["direction"] == "internal"
