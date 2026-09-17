"""Phase 3 tests: IPv6 flows + direction, QUIC labeling, protocol banners, DHCP."""

from __future__ import annotations

from tests.test_step1 import _analyze_and_wait, _upload


def _analyze(client, pcap: str) -> str:
    capture_id = _upload(client, pcap)
    job = _analyze_and_wait(client, capture_id)
    assert job["status"] == "completed", job
    return capture_id


def _all_flows(client, capture_id: str) -> list:
    flows, offset = [], 0
    while True:
        page = client.get(f"/api/flows?capture_id={capture_id}&limit=500&offset={offset}").json()
        flows.extend(page["items"])
        offset += page["limit"]
        if offset >= page["total"]:
            break
    return flows


# ---------------- IPv6 ----------------


def test_ipv6_flows_and_direction(client):
    capture_id = _analyze(client, "ipv6_traffic.pcap")
    flows = _all_flows(client, capture_id)
    by_dport = {f["destination_port"]: f for f in flows}

    # DNS over IPv6: unique-local ↔ unique-local → internal
    dns = by_dport[53]
    assert dns["source_ip"] == "fd00::42"
    assert dns["destination_ip"] == "fd00::1"
    assert dns["application_protocol"] == "DNS"
    assert dns["direction"] == "internal"

    # HTTP over IPv6: unique-local → global → outbound
    http = by_dport[80]
    assert http["source_ip"] == "fd00::42"
    assert http["destination_ip"] == "2606:4700:4700::1111"
    assert http["application_protocol"] == "HTTP"
    assert http["direction"] == "outbound"
    assert http["packets"] == 2  # request + response


def test_ipv6_dns_transaction(client):
    capture_id = _analyze(client, "ipv6_traffic.pcap")
    dns = client.get(f"/api/protocols/dns?capture_id={capture_id}").json()["items"]
    assert len(dns) == 1
    t = dns[0]
    assert t["client_ip"] == "fd00::42"
    assert t["query_name"].rstrip(".") == "example.org"
    assert t["rcode"] == 0
    assert t["latency"] is not None and t["latency"] > 0


def test_ipv6_hosts_profiled(client):
    capture_id = _analyze(client, "ipv6_traffic.pcap")
    hosts = {h["ip"]: h for h in client.get(f"/api/hosts?capture_id={capture_id}").json()}
    assert "fd00::42" in hosts
    assert "fd00::1" in hosts
    assert "2606:4700:4700::1111" in hosts
    assert hosts["fd00::42"]["is_internal"] is True
    assert hosts["2606:4700:4700::1111"]["is_internal"] is False
    # DNS server exposed :53 → role
    assert hosts["fd00::1"]["role"] == "DNS server"
    # HTTP answer hostname comes from the AAAA answer record
    assert hosts["2606:4700:4700::1111"]["hostname"] == "example.org"


# ---------------- QUIC ----------------


def test_quic_traffic_labeled(client):
    capture_id = _analyze(client, "quic_traffic.pcap")
    flows = _all_flows(client, capture_id)
    assert flows, "QUIC flows must be reconstructed over UDP"
    for f in flows:
        assert f["transport_protocol"] == "UDP"
        assert f["application_protocol"] == "QUIC"
        assert f["destination_ip"] == "151.101.1.69"
        assert f["direction"] == "outbound"
    # protocol counts include QUIC in the capture summary
    capture = client.get(f"/api/captures/{capture_id}").json()
    assert capture["summary"]["protocol_counts"].get("QUIC", 0) >= 5


# ---------------- Protocol banners ----------------


def test_protocol_banners_extracted(client):
    capture_id = _analyze(client, "protocol_banners.pcap")
    # banners live in packet metadata (evidence store) + hostnames in host profiles
    hosts = {h["ip"]: h for h in client.get(f"/api/hosts?capture_id={capture_id}").json()}
    # SSH server host gets its banner hostname
    ssh_srv = hosts["93.184.216.51"]
    assert ssh_srv["role"] == "SSH server"
    mail_srv = hosts["93.184.216.50"]
    assert mail_srv["role"] == "Mail server"
    assert mail_srv["hostname"] == "mail.example.com"
    ftp_srv = hosts["93.184.216.52"]
    assert ftp_srv["hostname"] == "ftp.example.com"

    # banner text visible via flow evidence drill-down
    flows = _all_flows(client, capture_id)
    ssh_flow = next(f for f in flows if f["destination_port"] == 22)
    detail = client.get(f"/api/flows/{ssh_flow['id']}").json()
    banners = [
        p["metadata"].get("ssh.banner") for p in detail["packet_evidence"] if p["metadata"].get("ssh.banner")
    ]
    assert banners, "SSH banner must be present in packet evidence"
    assert banners[0].startswith("SSH-2.0-OpenSSH")


# ---------------- DHCP ----------------


def test_dhcp_lease_flow_and_hostname(client):
    capture_id = _analyze(client, "dhcp_lease.pcap")
    flows = _all_flows(client, capture_id)
    dhcp_flows = [f for f in flows if f["application_protocol"] == "DHCP"]
    assert dhcp_flows, "DHCP flows must be labeled"
    # DORA: DISCOVER+REQUEST (68→67) and OFFER+ACK (67→68) aggregate to 2 flows
    assert len(dhcp_flows) == 2

    # client host carries its DHCP hostname
    hosts = {h["ip"]: h for h in client.get(f"/api/hosts?capture_id={capture_id}").json()}
    client_host = hosts["192.168.1.42"]
    assert client_host["hostname"] == "ws-laptop-01"

    # DHCP conversation appears in the timeline
    events = client.get(f"/api/timeline?capture_id={capture_id}&limit=1000").json()["items"]
    dhcp_events = [e for e in events if e["protocol"] == "DHCP"]
    assert len(dhcp_events) >= 2  # udp_session events typed DHCP


# ---------------- Unit: is_private_ip over IPv6 ----------------


def test_is_private_ip_v6_unit():
    from app.services.flow_builder import is_private_ip

    # unique-local
    assert is_private_ip("fd00::42")
    assert is_private_ip("fc00::1")
    # link-local
    assert is_private_ip("fe80::1")
    assert is_private_ip("FE80::A")
    # loopback
    assert is_private_ip("::1")
    # global
    assert not is_private_ip("2606:4700:4700::1111")
    assert not is_private_ip("2001:db8::1")
    # v4 unchanged
    assert is_private_ip("192.168.1.1")
    assert not is_private_ip("8.8.8.8")
