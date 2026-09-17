"""Phase 5 tests: cases, alert triage (tags/notes), and HTML report generation."""

from __future__ import annotations

from tests.test_step1 import _analyze_and_wait, _upload


def _analyze(client, pcap: str) -> str:
    capture_id = _upload(client, pcap)
    job = _analyze_and_wait(client, capture_id)
    assert job["status"] == "completed", job
    return capture_id


def _alerts(client, capture_id: str) -> list:
    return client.get(f"/api/alerts?capture_id={capture_id}&limit=500").json()["items"]


# ---------------- Cases ----------------


def test_case_create_list_detail(client):
    resp = client.post("/api/cases", json={"name": "Incident-42", "description": "weird traffic"})
    assert resp.status_code == 201, resp.text
    case = resp.json()
    assert case["name"] == "Incident-42"
    assert case["status"] == "open"
    assert case["captures"] == []

    listing = client.get("/api/cases").json()
    assert any(c["id"] == case["id"] for c in listing)

    detail = client.get(f"/api/cases/{case['id']}").json()
    assert detail["stats"]["capture_count"] == 0


def test_case_add_remove_captures_and_stats(client):
    cap1 = _analyze(client, "c2_beacon.pcap")
    cap2 = _analyze(client, "port_scan.pcap")

    case = client.post("/api/cases", json={"name": "Multi-capture case"}).json()
    cid = case["id"]

    for cap in (cap1, cap2):
        resp = client.post(f"/api/cases/{cid}/captures", json={"capture_id": cap})
        assert resp.status_code == 200, resp.text
    detail = client.get(f"/api/cases/{cid}").json()
    assert detail["stats"]["capture_count"] == 2
    assert len(detail["captures"]) == 2
    assert detail["stats"]["total_alerts"] > 0
    assert detail["stats"]["total_packets"] > 100
    # incidents deduped across captures, sorted by score
    scores = [i["max_score"] for i in detail["stats"]["incidents"]]
    assert scores == sorted(scores, reverse=True)

    # duplicate add is a no-op
    client.post(f"/api/cases/{cid}/captures", json={"capture_id": cap1})
    assert client.get(f"/api/cases/{cid}").json()["stats"]["capture_count"] == 2

    # remove
    resp = client.delete(f"/api/cases/{cid}/captures/{cap2}")
    assert resp.status_code == 200
    assert resp.json()["stats"]["capture_count"] == 1


def test_case_merged_timeline(client):
    cap1 = _analyze(client, "c2_beacon.pcap")
    cap2 = _analyze(client, "normal_traffic.pcap")
    case = client.post("/api/cases", json={"name": "timeline case"}).json()
    client.post(f"/api/cases/{case['id']}/captures", json={"capture_id": cap1})
    client.post(f"/api/cases/{case['id']}/captures", json={"capture_id": cap2})

    events = client.get(f"/api/cases/{case['id']}/timeline").json()
    assert len(events) > 50  # both captures' events merged
    ts = [e["timestamp"] for e in events]
    assert ts == sorted(ts), "merged timeline must be chronological"

    # event_type filter narrows server-side
    alerts_only = client.get(f"/api/cases/{case['id']}/timeline?event_type=alert").json()
    assert all(e["event_type"] == "alert" for e in alerts_only)
    assert len(alerts_only) >= 1


def test_case_close_and_delete(client):
    case = client.post("/api/cases", json={"name": "temp"}).json()
    closed = client.post(f"/api/cases/{case['id']}/close").json()
    assert closed["status"] == "closed"
    resp = client.delete(f"/api/cases/{case['id']}")
    assert resp.status_code == 200
    assert client.get(f"/api/cases/{case['id']}").status_code == 404


def test_case_not_found(client):
    assert client.get("/api/cases/missing").status_code == 404


# ---------------- Alert triage ----------------


def test_alert_triage_tags_and_note(client):
    capture_id = _analyze(client, "c2_beacon.pcap")
    alert_id = _alerts(client, capture_id)[0]["id"]

    # tag + note
    resp = client.patch(
        f"/api/alerts/{alert_id}",
        json={"tags": ["confirmed"], "note": "checked with John — real C2"},
    )
    assert resp.status_code == 200, resp.text
    updated = resp.json()
    assert updated["tags"] == ["confirmed"]
    assert updated["note"] == "checked with John — real C2"
    assert updated["acknowledged"] is False  # untouched

    # partial update: acknowledge only, tags/note preserved
    updated = client.patch(f"/api/alerts/{alert_id}", json={"acknowledged": True}).json()
    assert updated["acknowledged"] is True
    assert updated["tags"] == ["confirmed"]

    # bad tag rejected
    resp = client.patch(f"/api/alerts/{alert_id}", json={"tags": ["bogus"]})
    assert resp.status_code == 400
    assert "bogus" in resp.json()["detail"]

    # clear note
    updated = client.patch(f"/api/alerts/{alert_id}", json={"note": ""}).json()
    assert updated["note"] is None

    # unknown alert
    assert client.patch("/api/alerts/missing", json={"note": "x"}).status_code == 404


# ---------------- Report ----------------


def test_capture_report_html(client):
    capture_id = _analyze(client, "c2_beacon.pcap")
    resp = client.get(f"/api/captures/{capture_id}/report")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    body = resp.text
    # structure and content markers
    assert "Network Investigation Report" in body
    assert "c2_beacon.pcap" in body
    assert "Alerts (" in body
    assert "Beaconing" in body  # rule title appears in report
    assert "Correlated Incidents" in body
    assert "Top Flows by Volume" in body
    # alert evidence present: reasons with details
    assert "periodic" in body.lower()
    # no raw template leaks
    assert "{%" not in body and "{{" not in body


def test_capture_report_requires_analysis(client):
    from tests.test_step1 import _upload

    capture_id = _upload(client, "tcp_problems.pcap")  # uploaded, NOT analyzed
    resp = client.get(f"/api/captures/{capture_id}/report")
    assert resp.status_code == 409


def test_capture_report_not_found(client):
    assert client.get("/api/captures/missing/report").status_code == 404


def test_report_clean_capture(client):
    """A clean capture renders a report with the 'looks clean' note."""
    capture_id = _analyze(client, "normal_traffic.pcap")
    body = client.get(f"/api/captures/{capture_id}/report").text
    assert "No alerts were raised" in body


def test_case_incidents_counted_once_per_capture(client):
    """Regression: incidents were extended once per ALERT inside the loop —
    a capture with 3 alerts and 2 incidents reported 6 before dedupe."""
    cap = _analyze(client, "c2_beacon.pcap")
    assert cap

    case = client.post("/api/cases", json={"name": "Incident count case"}).json()
    cid = case["id"]
    client.post(f"/api/cases/{cid}/captures", json={"capture_id": cap})

    detail = client.get(f"/api/cases/{cid}").json()

    # capture-level incidents, straight from the analysis summary
    from app.core.database import SessionLocal
    from app.db.orm import CaptureModel

    db = SessionLocal()
    try:
        capture = db.get(CaptureModel, cap)
        summary_incidents = (capture.summary or {}).get("incidents", [])
    finally:
        db.close()

    reported = detail["stats"]["incidents"]
    # the case must report each incident once (dedupe key = source+rules;
    # distinct incidents from ONE capture must all survive)
    assert len(reported) == len(summary_incidents), (
        f"expected {len(summary_incidents)} incidents, got {len(reported)}"
    )
