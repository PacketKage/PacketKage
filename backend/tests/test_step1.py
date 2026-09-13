"""Step 1 end-to-end tests: upload → analyze → job progress → persisted results."""
from __future__ import annotations

import time
from pathlib import Path

from tests.conftest import TESTDATA


def _upload(client, pcap_name: str) -> str:
    path = TESTDATA / pcap_name
    with open(path, "rb") as f:
        resp = client.post(
            "/api/captures", files={"file": (pcap_name, f, "application/octet-stream")}
        )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _analyze_and_wait(client, capture_id: str, parser: str | None = None, timeout: float = 30.0) -> dict:
    body = {"parser": parser} if parser else None
    resp = client.post(f"/api/captures/{capture_id}/analyze", json=body)
    assert resp.status_code == 202, resp.text
    job_id = resp.json()["id"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] in ("completed", "failed"):
            return job
        time.sleep(0.1)
    raise AssertionError("job did not finish in time")


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_parsers_available(client):
    resp = client.get("/api/captures/meta/parsers")
    assert resp.status_code == 200
    assert resp.json()["scapy"] is True


def test_upload_rejects_bad_extension(client):
    resp = client.post(
        "/api/captures", files={"file": ("evil.txt", b"hello", "text/plain")}
    )
    assert resp.status_code == 400


def test_upload_creates_capture(client):
    capture_id = _upload(client, "normal_traffic.pcap")
    resp = client.get(f"/api/captures/{capture_id}")
    body = resp.json()
    assert body["filename"] == "normal_traffic.pcap"
    assert body["status"] == "created"
    assert body["size_bytes"] > 0


def test_list_captures(client):
    _upload(client, "normal_traffic.pcap")
    _upload(client, "port_scan.pcap")
    resp = client.get("/api/captures")
    assert resp.status_code == 200
    assert len(resp.json()) >= 2


def test_analysis_end_to_end_normal(client):
    capture_id = _upload(client, "normal_traffic.pcap")
    job = _analyze_and_wait(client, capture_id)
    assert job["status"] == "completed", job
    assert job["progress"] == 100
    assert job["result"]["parser"] == "scapy"
    assert job["result"]["packets"] == 12

    capture = client.get(f"/api/captures/{capture_id}").json()
    assert capture["status"] == "completed"
    assert capture["analysis_progress"] == 100
    assert capture["packet_count"] == 12
    assert capture["first_packet_ts"] is not None
    # 6 DNS + 4 HTTP + 2 TLS packets
    protocols = capture["summary"]["protocol_counts"]
    assert protocols.get("DNS") == 6
    assert protocols.get("HTTP") == 4
    assert protocols.get("TLS") == 2


def test_analysis_port_scan(client):
    capture_id = _upload(client, "port_scan.pcap")
    job = _analyze_and_wait(client, capture_id)
    assert job["status"] == "completed", job
    capture = client.get(f"/api/captures/{capture_id}").json()
    assert capture["packet_count"] == 100
    top_talker = capture["summary"]["top_talkers"][0]
    assert top_talker["ip"] == "192.168.1.42"  # the scanner


def test_analysis_dns_tunneling_counts(client):
    capture_id = _upload(client, "dns_tunneling.pcap")
    job = _analyze_and_wait(client, capture_id)
    assert job["status"] == "completed"
    capture = client.get(f"/api/captures/{capture_id}").json()
    assert capture["packet_count"] == 128
    assert capture["summary"]["protocol_counts"]["DNS"] == 128


def test_analysis_failure_handled(client, monkeypatch):
    """A corrupt file must mark the capture failed, not crash the app."""
    capture_id = _upload(client, "normal_traffic.pcap")
    # overwrite stored bytes with garbage
    from app.core.database import SessionLocal
    from app.db.orm import CaptureModel

    db = SessionLocal()
    capture = db.get(CaptureModel, capture_id)
    Path(capture.stored_path).write_bytes(b"this is not a pcap file")
    db.commit()
    db.close()

    resp = client.post(f"/api/captures/{capture_id}/analyze")
    assert resp.status_code == 202
    job_id = resp.json()["id"]
    deadline = time.time() + 10
    while time.time() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] in ("completed", "failed"):
            break
        time.sleep(0.1)
    assert job["status"] == "failed"
    capture = client.get(f"/api/captures/{capture_id}").json()
    assert capture["status"] == "failed"
    assert capture["error"] is not None


def test_analyze_missing_capture(client):
    resp = client.post("/api/captures/nonexistent/analyze")
    assert resp.status_code == 404


def test_unknown_parser_rejected(client):
    capture_id = _upload(client, "normal_traffic.pcap")
    resp = client.post(f"/api/captures/{capture_id}/analyze", json={"parser": "zeek"})
    assert resp.status_code == 400
    assert "Unknown parser" in resp.json()["detail"]


def test_tshark_parser_unavailable_graceful(client, monkeypatch):
    capture_id = _upload(client, "normal_traffic.pcap")
    # Force "tshark unavailable" regardless of the host env so the
    # unavailable-parser path is deterministic (tshark IS installed on
    # some dev machines, which made the old assumption flaky).
    from app.parsers import registry as _registry

    class _Unavailable:
        name = "tshark"
        description = "forced unavailable for test"

        def available(self) -> bool:
            return False

    monkeypatch.setitem(_registry._parsers, "tshark", _Unavailable())  # noqa: SLF001
    resp = client.post(f"/api/captures/{capture_id}/analyze", json={"parser": "tshark"})
    assert resp.status_code == 400
    assert "not available" in resp.json()["detail"]


def test_jobs_listing(client):
    capture_id = _upload(client, "normal_traffic.pcap")
    _analyze_and_wait(client, capture_id)
    resp = client.get("/api/jobs")
    assert resp.status_code == 200
    assert any(j["status"] == "completed" for j in resp.json())


def test_job_events_stream_is_valid_json(client):
    """Regression: the SSE /events stream must emit parseable JSON snapshots.

    An f-string over the model_dump dict once emitted Python dict repr
    (single quotes, bare None) — JSON.parse rejected every event in the
    browser, so job progress never reached the UI and captures appeared
    stuck in 'analyzing' forever. This locks the wire format.
    """
    import json as _json

    capture_id = _upload(client, "normal_traffic.pcap")
    resp = client.post(f"/api/captures/{capture_id}/analyze")
    assert resp.status_code == 202, resp.text
    job_id = resp.json()["id"]

    # wait for the job to finish so the SSE stream (opened below) delivers
    # a terminal snapshot immediately
    deadline = time.time() + 30.0
    while time.time() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] in ("completed", "failed"):
            break
        time.sleep(0.1)
    assert job["status"] == "completed", job

    resp = client.get(f"/api/jobs/{job_id}/events")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")

    # FastAPI's TestClient buffers the full SSE response; the stream closes
    # itself after the terminal snapshot is sent.
    body = resp.text
    data_lines = [
        line[len("data: "):] for line in body.splitlines() if line.startswith("data: ")
    ]
    assert data_lines, f"no SSE data events in response: {body!r}"

    snapshots = []
    for line in data_lines:
        parsed = _json.loads(line)  # raises on Python-repr regression
        snapshots.append(parsed)

    assert snapshots[-1]["status"] == "completed"
    assert snapshots[-1]["id"] == job_id
    assert snapshots[-1]["progress"] == 100


def test_scapy_parser_normalization_direct():
    """Unit-level: parser layer returns normalized packets, no scapy objects leak."""
    from app.parsers import ScapyParser

    parser = ScapyParser()
    parsed = parser.parse_file(str(TESTDATA / "dns_tunneling.pcap"))
    assert parsed.parser_used == "scapy"
    assert len(parsed.packets) == 128
    pkt = parsed.packets[0]
    assert pkt.source_ip == "192.168.1.42"
    assert pkt.destination_ip == "192.168.1.1"
    assert pkt.protocol == "DNS"
    assert pkt.transport == "UDP"
    assert pkt.source_port == 33400
    assert pkt.destination_port == 53
    assert "dns.query" in pkt.metadata
    assert not hasattr(pkt, "original")  # scapy internals must not leak


def test_upload_rejects_bad_magic_bytes(client):
    """Correct extension but non-pcap content must be rejected at upload time."""
    resp = client.post(
        "/api/captures",
        files={"file": ("evil.pcap", b"this is not a pcap file", "application/octet-stream")},
    )
    assert resp.status_code == 400
    assert "magic" in resp.json()["detail"]


def test_upload_rejects_empty_file(client):
    resp = client.post(
        "/api/captures",
        files={"file": ("empty.pcap", b"", "application/octet-stream")},
    )
    assert resp.status_code == 400


def test_upload_accepts_all_pcap_magics(client):
    """little/big-endian pcap and pcapng magic bytes all pass the content check."""
    import io
    from pathlib import Path

    for magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"):
        body = magic + b"\x00" * 32
        resp = client.post(
            "/api/captures",
            files={"file": (f"m_{magic.hex()}.pcap", io.BytesIO(body), "application/octet-stream")},
        )
        assert resp.status_code == 201, f"magic {magic.hex()} rejected"
        stored = resp.json().get("stored_path")
        if stored:
            Path(stored).unlink(missing_ok=True)


def test_upload_size_limit_aborts_early(client, monkeypatch):
    """Oversized uploads are cut off during streaming — not buffered fully in RAM."""
    import io

    import app.api.captures as captures_module

    monkeypatch.setattr(captures_module.settings, "max_upload_bytes", 1024)
    # 3MB of valid-magic data — the stream must abort after the first chunks
    body = b"\xd4\xc3\xb2\xa1" + b"\x00" * (3 * 1024 * 1024)
    resp = client.post(
        "/api/captures",
        files={"file": ("big.pcap", io.BytesIO(body), "application/octet-stream")},
    )
    assert resp.status_code == 413
    # no truncated leftovers in the upload dir
    upload_dir = captures_module.settings.upload_dir
    leftovers = [p for p in upload_dir.iterdir() if p.name.endswith("big.pcap")]
    assert leftovers == []


def test_concurrent_analyze_single_job(client):
    """H6 regression: two simultaneous POST /analyze → exactly one 202 + one 409.

    The old check-then-submit let both requests pass the status check before
    either set 'queued', so two analysis threads interleaved
    delete_for_capture + create_many → duplicate alert sets.
    The atomic guarded UPDATE makes the claim exclusive.
    """
    import concurrent.futures as cf

    capture_id = _upload(client, "port_scan.pcap")  # alert-producing capture

    def fire(_):
        return client.post(f"/api/captures/{capture_id}/analyze")

    with cf.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(fire, range(2)))

    codes = sorted(r.status_code for r in results)
    assert codes == [202, 409], f"expected one 202 + one 409, got {codes}"
    conflict = next(r for r in results if r.status_code == 409)
    assert "already" in conflict.json()["detail"].lower()

    # wait for the winning job, then verify no duplicate alerts
    from sqlalchemy import func, select

    from app.core.database import SessionLocal
    from app.db.orm import AlertModel, AnalysisJobModel, CaptureModel

    deadline = time.time() + 30
    while time.time() < deadline:
        with SessionLocal() as db:
            statuses = [
                j.status for j in db.scalars(
                    select(AnalysisJobModel).where(AnalysisJobModel.capture_id == capture_id)
                )
            ]
        if statuses and all(s in ("completed", "failed") for s in statuses):
            break
        time.sleep(0.1)

    with SessionLocal() as db:
        capture = db.get(CaptureModel, capture_id)
        assert capture is not None and capture.status == "completed", capture.status if capture else "?"
        dupes = db.scalar(
            select(func.count())
            .select_from(AlertModel)
            .where(AlertModel.capture_id == capture_id)
            .group_by(AlertModel.rule_name, AlertModel.source_ip, AlertModel.destination_ip)
            .having(func.count() > 1)
            .limit(1)
        )
        assert dupes is None, "duplicate alert rows for (rule, src, dst) — race leaked two runs"
        total = db.scalar(select(func.count()).select_from(AlertModel).where(AlertModel.capture_id == capture_id))
    assert total is not None and total > 0
