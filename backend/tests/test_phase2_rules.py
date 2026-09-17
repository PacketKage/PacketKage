"""Phase 2 tests: new detection rules (ARP spoofing, lateral movement, DGA,
exfiltration, low-and-slow beaconing) + alert correlation into incidents."""

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


# ---------------- ARP spoofing ----------------


def test_arp_spoofing_alert(client):
    capture_id, alerts = _analyze_and_alerts(client, "arp_spoofing.pcap")
    rules = _rules(alerts)
    spoofs = rules.get("arp_spoofing", [])
    assert len(spoofs) == 1
    a = spoofs[0]
    # gateway IP claimed by both legit MAC and attacker MAC
    assert a["source_ip"] == "192.168.1.1"
    assert len(a["evidence"]["macs"]) == 2
    assert "aa:bb:cc:dd:ee:99" in a["evidence"]["macs"]
    assert a["evidence"]["gratuitous_arp_count"] >= 5
    assert a["score"] >= 60
    assert a["severity"] in ("high", "critical")
    assert any("multiple MAC" in r["reason"] for r in a["reasons"])
    assert a["explanation"]


# ---------------- Lateral movement ----------------


def test_lateral_movement_alert(client):
    capture_id, alerts = _analyze_and_alerts(client, "lateral_movement.pcap")
    rules = _rules(alerts)
    lateral = rules.get("lateral_movement", [])
    assert len(lateral) == 1
    a = lateral[0]
    assert a["source_ip"] == "192.168.1.42"
    assert a["evidence"]["target_count"] == 5
    assert set(a["evidence"]["ports_used"]) == {22, 445, 3389, 5985}
    assert a["score"] >= 60
    assert a["severity"] in ("high", "critical")
    assert a["related_flow_ids"]  # drill-down evidence available
    assert any("fan-out" in r["reason"].lower() for r in a["reasons"])


# ---------------- DGA domains ----------------


def test_dga_alert(client):
    capture_id, alerts = _analyze_and_alerts(client, "dga_domains.pcap")
    rules = _rules(alerts)
    dga = rules.get("dga_domain", [])
    assert len(dga) == 1
    a = dga[0]
    assert a["source_ip"] == "192.168.1.42"
    assert a["evidence"]["count"] >= 8
    assert a["evidence"]["baseline_entropy"] < 4  # example.com etc are low-entropy
    # sample DGA names are consonant-heavy and high-entropy
    sample = a["evidence"]["high_entropy_domains"][0]
    assert len(sample.split(".")[0]) >= 10
    assert a["score"] >= 60
    assert a["explanation"]


# ---------------- Data exfiltration ----------------


def test_data_exfiltration_alert(client):
    capture_id, alerts = _analyze_and_alerts(client, "data_exfiltration.pcap")
    rules = _rules(alerts)
    exfil = rules.get("data_exfiltration", [])
    assert len(exfil) == 1
    a = exfil[0]
    assert a["source_ip"] == "192.168.1.42"
    assert a["destination_ip"] == "203.0.113.66"
    assert a["evidence"]["bytes"] >= 500_000  # ~400 packets * 1400 bytes
    assert a["evidence"]["destination_resolved_via_dns"] is False  # first contact
    assert a["score"] >= 60
    assert any(
        "first-contact" in r["reason"].lower() or "never resolved" in r["detail"].lower()
        for r in a["reasons"]
    )


# ---------------- Low-and-slow beaconing ----------------


def test_low_slow_beacon_alert(client):
    capture_id, alerts = _analyze_and_alerts(client, "low_slow_beacon.pcap")
    rules = _rules(alerts)
    slow = rules.get("low_slow_beaconing", [])
    assert len(slow) == 1
    a = slow[0]
    assert a["source_ip"] == "192.168.1.42"
    assert a["destination_ip"] == "198.51.100.77"
    assert a["destination_port"] == 443
    assert a["evidence"]["connection_count"] == 4
    assert abs(a["evidence"]["mean_interval"] - 300.0) < 5
    assert a["evidence"]["jitter_ratio"] < 0.2
    assert a["score"] >= 55
    assert "low-and-slow" in a["explanation"].lower() or "low and slow" in a["explanation"].lower()


# ---------------- No false positives on clean data ----------------


def test_new_rules_quiet_on_normal_traffic(client):
    """Benign traffic must not trigger any Phase 2 rules."""
    capture_id, alerts = _analyze_and_alerts(client, "normal_traffic.pcap")
    rules = _rules(alerts)
    for rule in ("arp_spoofing", "lateral_movement", "dga_domain", "data_exfiltration", "low_slow_beaconing"):
        assert rule not in rules, f"false positive: {rule}"
    high = [a for a in alerts if a["severity"] in ("high", "critical")]
    assert high == [], [a["title"] for a in high]


# ---------------- Alert correlation → incidents ----------------


def test_incidents_in_capture_summary(client):
    """C2 beacon capture: its correlated alerts (beaconing + suspicious_port +
    connection_without_dns) merge into one incident per host."""
    capture_id, alerts = _analyze_and_alerts(client, "c2_beacon.pcap")
    capture = client.get(f"/api/captures/{capture_id}").json()
    incidents = capture["summary"]["incidents"]
    assert incidents, "expected correlated incidents in summary"
    # all alerts share source host 192.168.1.42 within the capture window
    top = incidents[0]
    assert top["source_ip"] == "192.168.1.42"
    assert top["alert_count"] >= 2
    assert top["max_score"] == max(a["score"] for a in alerts)
    assert "beaconing" in top["rule_names"]
    assert top["story"]
    assert top["severity"] in ("critical", "high")


def test_incidents_sorted_by_score(client):
    capture_id, alerts = _analyze_and_alerts(client, "dns_tunneling.pcap")
    incidents = client.get(f"/api/captures/{capture_id}").json()["summary"]["incidents"]
    scores = [i["max_score"] for i in incidents]
    assert scores == sorted(scores, reverse=True)
    assert incidents[0]["source_ip"] == "192.168.1.42"


def test_correlation_no_incidents_on_clean_data(client):
    capture_id, alerts = _analyze_and_alerts(client, "normal_traffic.pcap")
    summary = client.get(f"/api/captures/{capture_id}").json()["summary"]
    # clean traffic: no medium+ alerts from one host -> no incidents
    assert summary.get("incidents", []) == []


# ---------------- Unit: entropy + UA patterns ----------------


def test_shannon_entropy_unit():
    from app.services.suspicion_engine import _shannon_entropy

    assert _shannon_entropy("") == 0
    assert _shannon_entropy("aaaa") < 0.5  # pure repetition → ~0 bits
    assert abs(_shannon_entropy("ab") - 1.0) < 1e-9  # 50/50 → exactly 1 bit
    # random mix is high-entropy
    assert _shannon_entropy("xjqkwvbzptm") > 3.0


def test_ua_pattern_match_unit():
    import re

    from app.services.suspicion_engine import SUSPICIOUS_UA_PATTERNS

    ua = "sqlmap/1.7.2#stable (http://sqlmap.org)"
    assert any(re.search(p, ua) for p, _ in SUSPICIOUS_UA_PATTERNS)
    ua_clean = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    assert not any(re.search(p, ua_clean) for p, _ in SUSPICIOUS_UA_PATTERNS)
