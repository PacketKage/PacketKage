"""Step 4 tests: suspicion engine — every scenario must trigger its expected alerts."""

from __future__ import annotations

from tests.test_step1 import _analyze_and_wait, _upload


def _analyze_and_alerts(client, pcap: str) -> tuple[str, list]:
    capture_id = _upload(client, pcap)
    job = _analyze_and_wait(client, capture_id)
    assert job["status"] == "completed", job
    resp = client.get(f"/api/alerts?capture_id={capture_id}&limit=500")
    assert resp.status_code == 200
    return capture_id, resp.json()["items"]


def _rules(alerts: list) -> dict[str, list]:
    by_rule: dict[str, list] = {}
    for a in alerts:
        by_rule.setdefault(a["rule_name"], []).append(a)
    return by_rule


# ---------------- Port scan ----------------


def test_port_scan_alert(client):
    capture_id, alerts = _analyze_and_alerts(client, "port_scan.pcap")
    rules = _rules(alerts)
    scans = rules.get("port_scan", [])
    assert len(scans) == 1
    alert = scans[0]
    assert alert["source_ip"] == "192.168.1.42"
    assert alert["destination_ip"] == "192.168.1.25"
    assert alert["score"] >= 60
    assert alert["severity"] in ("high", "critical")
    assert alert["evidence"]["ports_probed"][0] == 20
    assert len(alert["evidence"]["ports_probed"]) == 100
    assert len(alert["reasons"]) >= 3
    assert all("detail" in r and "reason" in r and r["weight"] > 0 for r in alert["reasons"])
    assert alert["explanation"]
    assert alert["related_flow_ids"]  # drill-down to flows available


# ---------------- Beaconing ----------------


def test_c2_beacon_alerts(client):
    capture_id, alerts = _analyze_and_alerts(client, "c2_beacon.pcap")
    rules = _rules(alerts)

    # beaconing rule
    beacons = rules.get("beaconing", [])
    assert len(beacons) == 1
    b = beacons[0]
    assert b["source_ip"] == "192.168.1.42"
    assert b["destination_ip"] == "185.234.72.19"
    assert b["destination_port"] == 4444
    assert b["evidence"]["connection_count"] == 40
    assert abs(b["evidence"]["mean_interval"] - 30.0) < 1.0
    assert b["evidence"]["jitter_ratio"] < 0.1
    assert b["score"] >= 80  # periodicity + suspicious port
    assert b["severity"] == "critical"
    assert any("periodic" in r["reason"].lower() for r in b["reasons"])
    assert any("4444" in r["detail"] for r in b["reasons"])

    # suspicious port rule also fires
    sport_alerts = rules.get("suspicious_port", [])
    assert len(sport_alerts) >= 1
    assert all(a["destination_port"] == 4444 for a in sport_alerts)

    # connection without DNS (no DNS in this capture at all)
    nodns = rules.get("connection_without_dns", [])
    assert len(nodns) >= 1
    assert nodns[0]["destination_ip"] == "185.234.72.19"


# ---------------- DNS tunneling ----------------


def test_dns_tunneling_alerts(client):
    capture_id, alerts = _analyze_and_alerts(client, "dns_tunneling.pcap")
    rules = _rules(alerts)

    tunnel = rules.get("dns_tunneling", [])
    assert len(tunnel) == 1
    t = tunnel[0]
    assert t["source_ip"] == "192.168.1.42"
    assert t["score"] >= 60
    assert t["evidence"]["query_count"] == 64
    assert t["evidence"]["longest_label_chars"] >= 30
    assert t["evidence"]["unique_subdomains"] >= 50
    assert t["evidence"]["nxdomain_count"] == 64
    assert "tunnel.example.net" in t["evidence"]["sample_query"]
    assert any("long" in r["reason"].lower() for r in t["reasons"])

    # NXDOMAIN burst rule also fires
    nx = rules.get("nxdomain_burst", [])
    assert len(nx) == 1
    assert nx[0]["evidence"]["nxdomain_count"] == 64
    assert nx[0]["evidence"]["rate"] == 1.0


# ---------------- TCP problems ----------------


def test_tcp_problems_alerts(client):
    capture_id, alerts = _analyze_and_alerts(client, "tcp_problems.pcap")
    rules = _rules(alerts)
    failures = rules.get("excessive_connection_failures", [])
    assert len(failures) >= 1
    # 5 unanswered to port 81 + 1 reset to 8080 (never saw SYN-ACK) = 6 failed flows
    f = next(a for a in failures if a["destination_ip"] == "93.184.216.34")
    assert f["evidence"]["failed_count"] == 6
    assert f["evidence"]["ports"] == [81, 8080]
    assert f["score"] >= 40


# ---------------- Normal traffic (no false positives) ----------------


def test_normal_traffic_no_critical_alerts(client):
    """Benign browsing must NOT produce high/critical alerts (false-positive check)."""
    capture_id, alerts = _analyze_and_alerts(client, "normal_traffic.pcap")
    high = [a for a in alerts if a["severity"] in ("high", "critical")]
    assert high == [], [a["title"] for a in high]
    # at most low/info noise (e.g., direct IP HTTP on port 80 is excluded)
    assert all(a["score"] < 60 for a in alerts)


# ---------------- Alert ordering + determinism ----------------


def test_alerts_sorted_by_score(client):
    for pcap in ["port_scan.pcap", "c2_beacon.pcap", "dns_tunneling.pcap"]:
        _, alerts = _analyze_and_alerts(client, pcap)
        scores = [a["score"] for a in alerts]
        assert scores == sorted(scores, reverse=True), pcap


def test_alerts_deterministic(client):
    """Same capture analyzed twice -> same rule set and scores."""
    cap1, alerts1 = _analyze_and_alerts(client, "c2_beacon.pcap")
    cap2, alerts2 = _analyze_and_alerts(client, "c2_beacon.pcap")
    sig1 = sorted((a["rule_name"], a["score"], a["title"]) for a in alerts1)
    sig2 = sorted((a["rule_name"], a["score"], a["title"]) for a in alerts2)
    assert sig1 == sig2


# ---------------- Filters, ack, host augmentation ----------------


def test_alert_filters(client):
    capture_id, alerts = _analyze_and_alerts(client, "c2_beacon.pcap")
    critical = client.get(f"/api/alerts?capture_id={capture_id}&severity=critical").json()["items"]
    assert all(a["severity"] == "critical" for a in critical)
    assert len(critical) >= 1
    high_score = client.get(f"/api/alerts?capture_id={capture_id}&min_score=80").json()["items"]
    assert all(a["score"] >= 80 for a in high_score)
    only_rule = client.get(f"/api/alerts?capture_id={capture_id}&rule=beaconing").json()["items"]
    assert all(a["rule_name"] == "beaconing" for a in only_rule)
    assert len(only_rule) == 1


def test_alert_acknowledge(client):
    capture_id, alerts = _analyze_and_alerts(client, "port_scan.pcap")
    alert_id = alerts[0]["id"]
    assert alerts[0]["acknowledged"] is False
    resp = client.post(f"/api/alerts/{alert_id}/ack", json={"acknowledged": True})
    assert resp.status_code == 200
    assert resp.json()["acknowledged"] is True
    # un-ack
    resp = client.post(f"/api/alerts/{alert_id}/ack", json={"acknowledged": False})
    assert resp.json()["acknowledged"] is False


def test_alert_not_found(client):
    resp = client.get("/api/alerts/nonexistent")
    assert resp.status_code == 404


def test_hosts_augmented_with_alerts(client):
    """Host profiles carry alert counts (Module H: suspicious behaviors)."""
    capture_id, alerts = _analyze_and_alerts(client, "c2_beacon.pcap")
    hosts = {h["ip"]: h for h in client.get(f"/api/hosts?capture_id={capture_id}").json()}
    ws = hosts["192.168.1.42"]
    expected = len([a for a in alerts if a["source_ip"] == "192.168.1.42"])
    assert ws["behavior_summary"]["alert_count"] == expected
    assert ws["behavior_summary"]["high_severity_alert_count"] >= 1
    c2 = hosts["185.234.72.19"]
    assert c2["behavior_summary"]["alert_count"] == 0  # destination not source


def test_capture_summary_alert_stats(client):
    capture_id, alerts = _analyze_and_alerts(client, "c2_beacon.pcap")
    capture = client.get(f"/api/captures/{capture_id}").json()
    s = capture["summary"]["alert_summary"]
    assert s["total"] == len(alerts)
    assert s["by_severity"]["critical"] >= 1
    assert "beaconing" in s["by_rule"]
    assert s["max_score"] == max(a["score"] for a in alerts)


def test_job_result_includes_alerts(client):
    capture_id, _ = _analyze_and_alerts(client, "port_scan.pcap")
    jobs = client.get("/api/jobs").json()
    job = next(j for j in jobs if j["capture_id"] == capture_id and j["status"] == "completed")
    assert job["result"]["alerts"] >= 1


# ---------------- Unit: rule severity mapping ----------------


def test_severity_mapping_unit():
    from app.services.suspicion_engine import _severity_for

    assert _severity_for(85) == "critical"
    assert _severity_for(70) == "high"
    assert _severity_for(50) == "medium"
    assert _severity_for(25) == "low"
    assert _severity_for(10) == "info"


def test_alert_flow_evidence_links_are_real_ids(client):
    """Regression (audit C1): alerts must reference REAL persisted flow ids —
    never the "flowidx-N" placeholder. The AlertsPage deep link
    (/flows?flow=<id>) is dead evidence without this."""
    # port_scan/c2_beacon are flow-driven scenarios; dns_tunneling exercises
    # the packet-refs-only path (DNS rules legitimately carry no flow ids)
    for pcap in ("port_scan.pcap", "c2_beacon.pcap", "dns_tunneling.pcap"):
        capture_id, alerts = _analyze_and_alerts(client, pcap)
        assert alerts, f"{pcap}: expected alerts"

        flow_ids: set[str] = set()
        offset = 0
        while True:
            body = client.get(f"/api/flows?capture_id={capture_id}&limit=500&offset={offset}").json()
            flow_ids.update(f["id"] for f in body["items"])
            offset += len(body["items"])
            if offset >= body["total"] or not body["items"]:
                break

        flow_alerts = [a for a in alerts if a["related_flow_ids"]]
        if pcap != "dns_tunneling.pcap":
            assert flow_alerts, f"{pcap}: no alert carries flow evidence at all"
        for a in flow_alerts:
            bad = [r for r in a["related_flow_ids"] if r not in flow_ids]
            assert not bad, (
                f"{pcap}/{a['rule_name']}: flow ids {bad[:3]} don't exist — "
                f"evidence links are broken (flowidx placeholders?)"
            )
            assert all(not str(r).startswith("flowidx-") for r in a["related_flow_ids"])
