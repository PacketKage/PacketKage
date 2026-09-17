"""Step 6 tests: network engineering mode metrics."""

from __future__ import annotations

from tests.conftest import TESTDATA
from tests.test_step1 import _analyze_and_wait, _upload


def _metrics(client, pcap: str) -> dict:
    capture_id = _upload(client, pcap)
    job = _analyze_and_wait(client, capture_id)
    assert job["status"] == "completed", job
    resp = client.get(f"/api/engineer/metrics?capture_id={capture_id}")
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_metrics_normal_traffic(client):
    m = _metrics(client, "normal_traffic.pcap")
    assert m["total_packets"] == 12
    assert m["total_bytes"] > 0
    assert m["capture_duration_s"] > 35  # spans 3 domains x 20s
    assert m["avg_pps"] > 0
    assert m["protocol_distribution"]["DNS"] == 6
    assert m["transport_distribution"]["TCP"] == 6
    assert len(m["top_talkers"]) >= 2
    # clean capture => healthy or only info issues
    assert m["health"] in ("healthy", "warning")
    assert not any(i["severity"] == "high" for i in m["issues"])
    # DNS latency measured
    assert m["dns"]["avg_latency_ms"] is not None
    assert m["dns"]["avg_latency_ms"] < 100  # 20ms generated
    # timeseries buckets
    assert len(m["timeseries"]["pps"]) == 40
    assert len(m["timeseries"]["bandwidth"]) == 40


def test_metrics_tcp_problems_degraded(client):
    m = _metrics(client, "tcp_problems.pcap")
    tcp = m["tcp"]
    assert tcp["retransmissions"] >= 2  # 1 data + 1 SYN retrans
    assert tcp["syn_retransmissions"] == 1
    assert tcp["resets"] == 1
    assert tcp["failed_flows"] == 6
    assert tcp["failure_ratio"] > 0.5
    assert tcp["one_way_flows"] == 5  # unanswered port-81 flows (reset flow had reverse RST)

    issue_types = {i["issue"] for i in m["issues"]}
    assert "connection_failures" in issue_types
    assert "tcp_resets" in issue_types or "retransmissions" in issue_types
    assert m["health"] == "degraded"  # high-severity failure ratio


def test_metrics_dns_tunneling_dns_issues(client):
    m = _metrics(client, "dns_tunneling.pcap")
    assert m["dns"]["nxdomain_rate"] == 1.0
    issue_types = {i["issue"] for i in m["issues"]}
    assert "dns_nxdomain" in issue_types


def test_metrics_port_scan_failures(client):
    m = _metrics(client, "port_scan.pcap")
    tcp = m["tcp"]
    assert tcp["failed_flows"] == 100
    assert tcp["failure_ratio"] == 1.0
    assert m["health"] == "degraded"
    assert "connection_failures" in {i["issue"] for i in m["issues"]}
    # peak pps: 100 SYN in ~1s window
    assert m["peak_pps"] > 50


def test_metrics_bandwidth_values(client):
    m = _metrics(client, "dns_tunneling.pcap")
    # 128 dns packets over ~31.5s span
    assert m["total_packets"] == 128
    assert 3.5 < m["avg_pps"] < 4.5
    assert m["avg_bandwidth_bps"] > 0
    assert m["peak_bandwidth_bps"] >= m["avg_bandwidth_bps"]


def test_metrics_needs_capture(client):
    resp = client.get("/api/engineer/metrics?capture_id=missing")
    assert resp.status_code == 404


def test_engineer_metrics_unit_direct():
    """Unit: compute directly from parser + builder."""
    from app.parsers import ScapyParser
    from app.services.engineer_metrics import compute_engineer_metrics
    from app.services.flow_builder import FlowBuilder
    from app.services.protocol_extractor import extract_dns

    parsed = ScapyParser().parse_file(str(TESTDATA / "c2_beacon.pcap"))
    flows = FlowBuilder().build_from(parsed)
    dns = extract_dns(parsed)
    m = compute_engineer_metrics(parsed, flows, dns, bucket_count=10)
    assert m["total_packets"] == 120
    assert m["capture_duration_s"] >= 1165  # 39 * 30s
    assert m["tcp"]["flows"] == 40
    assert m["tcp"]["failed_flows"] == 0
    assert m["dns"]["transactions"] == 0
    assert m["health"] in ("healthy", "warning", "degraded")
