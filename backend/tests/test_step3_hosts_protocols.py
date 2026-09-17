"""Step 3 tests: host profiling + protocol extraction (DNS/HTTP/TLS)."""

from __future__ import annotations

from tests.conftest import TESTDATA
from tests.test_step1 import _analyze_and_wait, _upload


def _analyze(client, pcap: str) -> str:
    capture_id = _upload(client, pcap)
    job = _analyze_and_wait(client, capture_id)
    assert job["status"] == "completed", job
    return capture_id


# ---------------- Hosts ----------------


def test_host_profiles_built(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    resp = client.get(f"/api/hosts?capture_id={capture_id}")
    assert resp.status_code == 200
    hosts = resp.json()
    ips = {h["ip"] for h in hosts}
    assert ips == {"192.168.1.42", "192.168.1.1", "93.184.216.34"}

    by_ip = {h["ip"]: h for h in hosts}
    ws = by_ip["192.168.1.42"]
    assert ws["is_internal"] is True
    assert ws["packets_sent"] == 6  # 3 DNS queries + 2 HTTP requests + 1 TLS ClientHello
    assert ws["bytes_sent"] > 0
    assert "DNS" in ws["protocols"]

    dns_srv = by_ip["192.168.1.1"]
    # others connected TO dns server on port 53 => exposed service
    services = {s["port"]: s for s in dns_srv["services"]}
    assert 53 in services
    assert services[53]["service"] == "DNS"
    assert dns_srv["role"] == "DNS server"

    ext = by_ip["93.184.216.34"]
    # web server role: peers hit 80 and 443
    services = {s["port"]: s for s in ext["services"]}
    assert 80 in services and 443 in services
    assert ext["role"] == "Web server"
    assert ext["is_internal"] is False
    # hostname resolved via DNS answer
    assert ext["hostname"] in ("example.com", "github.com", "wikipedia.org")


def test_host_detail(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    hosts = client.get(f"/api/hosts?capture_id={capture_id}").json()
    host_id = hosts[0]["id"]
    detail = client.get(f"/api/hosts/{host_id}").json()
    assert detail["id"] == host_id
    assert detail["behavior_summary"]["dominant_protocol"]
    assert detail["behavior_summary"]["services_exposed"] >= 0


def test_hosts_internal_filter(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    internal = client.get(f"/api/hosts?capture_id={capture_id}&internal=true").json()
    external = client.get(f"/api/hosts?capture_id={capture_id}&internal=false").json()
    assert all(h["is_internal"] for h in internal)
    assert all(not h["is_internal"] for h in external)
    assert {h["ip"] for h in internal} == {"192.168.1.42", "192.168.1.1"}
    assert {h["ip"] for h in external} == {"93.184.216.34"}


def test_port_scan_host_contacted_many_ports(client):
    capture_id = _analyze(client, "port_scan.pcap")
    hosts = {h["ip"]: h for h in client.get(f"/api/hosts?capture_id={capture_id}").json()}
    scanner = hosts["192.168.1.42"]
    assert scanner["role"] is None  # initiator, not a server
    assert len(scanner["contacted"]) == 100  # scanned 100 distinct ports
    target = hosts["192.168.1.25"]
    assert len(target["services"]) == 100  # all ports probed => exposed


# ---------------- DNS ----------------


def test_dns_transactions_paired(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    txns = client.get(f"/api/protocols/dns?capture_id={capture_id}").json()["items"]
    assert len(txns) == 3
    for t in txns:
        assert t["is_response"] is True
        assert t["rcode"] == 0
        assert t["latency"] is not None and t["latency"] > 0
        assert t["response_ips"] == ["93.184.216.34"]
        assert t["client_ip"] == "192.168.1.42"
        assert t["server_ip"] == "192.168.1.1"
    names = {t["query_name"].rstrip(".") for t in txns}
    assert names == {"example.com", "github.com", "wikipedia.org"}


def test_dns_tunneling_nxdomain(client):
    capture_id = _analyze(client, "dns_tunneling.pcap")
    txns = client.get(f"/api/protocols/dns?capture_id={capture_id}&rcode=3&limit=500").json()["items"]
    assert len(txns) == 64  # every tunneling query got NXDOMAIN
    assert all(t["query_name"].endswith(".tunnel.example.net.") for t in txns)


def test_dns_domain_filter(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    txns = client.get(f"/api/protocols/dns?capture_id={capture_id}&domain=github").json()["items"]
    assert len(txns) == 1
    assert "github.com" in txns[0]["query_name"]


# ---------------- HTTP ----------------


def test_http_transactions(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    txns = client.get(f"/api/protocols/http?capture_id={capture_id}").json()["items"]
    assert len(txns) == 2
    by_host = {t["host"]: t for t in txns}
    ex = by_host["example.com"]
    assert ex["method"] == "GET"
    assert ex["path"] == "/"
    assert ex["status_code"] == 200
    assert ex["request_len"] > 0 and ex["response_len"] > 0
    assert ex["client_ip"] == "192.168.1.42"
    assert ex["server_ip"] == "93.184.216.34"
    assert ex["server_port"] == 80
    gh = by_host["github.com"]
    assert gh["status_code"] == 404
    assert "PacketKageTest" in (gh["user_agent"] or "")


def test_http_status_filter(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    errors = client.get(f"/api/protocols/http?capture_id={capture_id}&status=404").json()["items"]
    assert len(errors) == 1
    assert errors[0]["host"] == "github.com"


# ---------------- TLS ----------------


def test_tls_sessions_with_sni(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    sessions = client.get(f"/api/protocols/tls?capture_id={capture_id}").json()["items"]
    assert len(sessions) >= 1
    sni = [s["sni"] for s in sessions if s["sni"]]
    assert "wikipedia.org" in sni
    wiki = next(s for s in sessions if s["sni"] == "wikipedia.org")
    assert wiki["client_ip"] == "192.168.1.42"
    assert wiki["server_ip"] == "93.184.216.34"
    assert wiki["server_port"] == 443
    assert wiki["packets"] >= 2
    assert wiki["bytes"] > 0


def test_tls_sni_filter(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    sessions = client.get(f"/api/protocols/tls?capture_id={capture_id}&sni=wikipedia").json()["items"]
    assert len(sessions) == 1
    assert sessions[0]["sni"] == "wikipedia.org"


# ---------------- Protocol stats (Module J) ----------------


def test_protocol_stats_summary(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    stats = client.get(f"/api/protocols/stats?capture_id={capture_id}").json()
    dns = stats["dns"]
    assert dns["transactions"] == 3
    assert dns["nxdomain_count"] == 0
    assert dns["unique_domains"] == 3
    assert any(d["value"] == "example.com" for d in dns["top_domains"])
    assert dns["avg_latency"] is not None

    http = stats["http"]
    assert http["transactions"] == 2
    assert http["status_codes"] == {"200": 1, "404": 1}
    assert http["methods"] == {"GET": 2}


def test_protocol_stats_tunneling_indicators(client):
    capture_id = _analyze(client, "dns_tunneling.pcap")
    stats = client.get(f"/api/protocols/stats?capture_id={capture_id}").json()
    dns = stats["dns"]
    assert dns["transactions"] == 64
    assert dns["nxdomain_count"] == 64
    assert dns["nxdomain_rate"] == 1.0
    longest = dns["longest_queries"][0]
    assert len(longest) > 50  # long encoded labels => tunneling indicator


def test_capture_summary_includes_step3(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    capture = client.get(f"/api/captures/{capture_id}").json()
    s = capture["summary"]
    assert s["host_count"] == 3
    assert s["internal_host_count"] == 2
    assert s["dns_summary"]["transactions"] == 3
    assert s["http_summary"]["transactions"] == 2
    assert s["tls_summary"]["sessions"] >= 1
    assert s["tls_summary"]["unique_sni"] >= 1


def test_job_result_counts(client):
    capture_id = _analyze(client, "normal_traffic.pcap")
    # find the job for this capture
    jobs = client.get("/api/jobs").json()
    job = next(j for j in jobs if j["capture_id"] == capture_id and j["status"] == "completed")
    r = job["result"]
    assert r["hosts"] == 3
    assert r["dns_transactions"] == 3
    assert r["http_transactions"] == 2
    assert r["tls_sessions"] >= 1


# ---------------- Unit level ----------------


def test_host_profiler_roles_unit():
    from app.parsers import ScapyParser
    from app.services.flow_builder import FlowBuilder
    from app.services.host_profiler import HostProfiler

    parsed = ScapyParser().parse_file(str(TESTDATA / "tcp_problems.pcap"))
    flows = FlowBuilder().build_from(parsed)
    hosts = HostProfiler().build_profiles(parsed, flows)
    by_ip = {h["ip"]: h for h in hosts}
    ws = by_ip["192.168.1.42"]
    ext = by_ip["93.184.216.34"]
    # ws initiated to 80, 8080, 81 => contacted includes those
    contacted_ports = {c["port"] for c in ws["contacted"]}
    assert {80, 8080, 81} <= contacted_ports
    # ext saw connections on 80 (2 flows), 8080, 81x5
    ext_services = {s["port"] for s in ext["services"]}
    assert {80, 8080, 81} <= ext_services
    assert ws["is_internal"] and not ext["is_internal"]
