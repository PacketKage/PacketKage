"""DELETE /api/captures/{id} regression tests.

Covers: 404s, full cascade across every capture-scoped table, PCAP file
cleanup, case-membership stripping, blocked-while-analyzing (409), failed
and never-analyzed captures, atomic rollback, unlink-failure tolerance and
the upload-dir containment guard.

NOTE: conftest's app_env purges and reloads every app.* module per test, so
ALL app imports here happen inside functions/bodies — never at module level
(a module-level import would bind to the pre-reload module and its engine).
"""

from __future__ import annotations

import time
from pathlib import Path

from tests.conftest import TESTDATA

SCOPED_TABLES = (
    "PacketModel",
    "FlowModel",
    "HostModel",
    "DNSTransactionModel",
    "HTTPTransactionModel",
    "TLSSessionModel",
    "AlertModel",
    "TimelineEventModel",
    "GraphEdgeModel",
    "AnalysisJobModel",
)


def _upload(client, pcap_name: str) -> str:
    path = TESTDATA / pcap_name
    with open(path, "rb") as f:
        resp = client.post("/api/captures", files={"file": (pcap_name, f, "application/octet-stream")})
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _analyze_and_wait(client, capture_id: str, timeout: float = 30.0) -> dict:
    resp = client.post(f"/api/captures/{capture_id}/analyze")
    assert resp.status_code == 202, resp.text
    job_id = resp.json()["id"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] in ("completed", "failed"):
            return job
        time.sleep(0.1)
    raise AssertionError("job did not finish in time")


def _orm(name: str):
    """Late-import an ORM class from the CURRENTLY loaded app modules."""
    from app.db import orm

    return getattr(orm, name)


def _stored_path(capture_id: str) -> str | None:
    from app.core.database import SessionLocal

    with SessionLocal() as db:
        capture = db.get(_orm("CaptureModel"), capture_id)
        return capture.stored_path if capture else None


def _count(model_name: str, capture_id: str) -> int:
    from sqlalchemy import func, select

    from app.core.database import SessionLocal

    model = _orm(model_name)
    with SessionLocal() as db:
        return int(
            db.scalar(select(func.count()).select_from(model).where(model.capture_id == capture_id)) or 0
        )


def _assert_all_scoped_tables_empty(capture_id: str) -> None:
    for model_name in SCOPED_TABLES:
        assert _count(model_name, capture_id) == 0, f"orphaned rows in {model_name}"


def test_delete_nonexistent_capture_404(client):
    resp = client.delete("/api/captures/nonexistent")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_delete_created_capture_removes_row_and_file(client):
    capture_id = _upload(client, "normal_traffic.pcap")
    stored = _stored_path(capture_id)
    assert stored and Path(stored).is_file()

    resp = client.delete(f"/api/captures/{capture_id}")
    assert resp.status_code == 200, resp.text
    assert resp.json()["file_removed"] is True

    assert client.get(f"/api/captures/{capture_id}").status_code == 404
    assert not Path(stored).exists()


def test_delete_completed_capture_cascades_every_table(client):
    capture_id = _upload(client, "c2_beacon.pcap")  # alerts + graph + timeline
    keep_id = _upload(client, "normal_traffic.pcap")
    _analyze_and_wait(client, capture_id)
    _analyze_and_wait(client, keep_id)

    # sanity: the capture produced derived rows in the tables we care about
    assert _count("PacketModel", capture_id) > 0
    assert _count("FlowModel", capture_id) > 0
    assert _count("AlertModel", capture_id) > 0
    assert _count("TimelineEventModel", capture_id) > 0
    assert _count("GraphEdgeModel", capture_id) > 0

    resp = client.delete(f"/api/captures/{capture_id}")
    assert resp.status_code == 200, resp.text

    _assert_all_scoped_tables_empty(capture_id)
    from app.core.database import SessionLocal

    with SessionLocal() as db:
        assert db.get(_orm("CaptureModel"), capture_id) is None

    # sibling capture completely untouched
    assert client.get(f"/api/captures/{keep_id}").status_code == 200
    assert _count("PacketModel", keep_id) > 0
    assert _count("FlowModel", keep_id) > 0


def test_delete_blocked_while_analyzing(client):
    """A queued/running analysis owns the row — deletion must 409, not race."""
    capture_id = _upload(client, "normal_traffic.pcap")
    resp = client.post(f"/api/captures/{capture_id}/analyze")
    assert resp.status_code == 202
    job_id = resp.json()["id"]

    # while the job is queued/running, deletion is refused with 409
    conflict = client.delete(f"/api/captures/{capture_id}")
    assert conflict.status_code == 409
    detail = conflict.json()["detail"].lower()
    assert "running" in detail or "analysis" in detail
    assert client.get(f"/api/captures/{capture_id}").status_code == 200  # still there

    # once finished, the same delete succeeds
    deadline = time.time() + 30
    while time.time() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] in ("completed", "failed"):
            break
        time.sleep(0.1)
    assert job["status"] == "completed"

    ok = client.delete(f"/api/captures/{capture_id}")
    assert ok.status_code == 200
    assert client.get(f"/api/captures/{capture_id}").status_code == 404


def test_delete_failed_capture_cleans_partial_data(client):
    """Analysis of a corrupt file leaves status=failed + partial rows — deletable."""
    capture_id = _upload(client, "normal_traffic.pcap")
    stored = _stored_path(capture_id)
    Path(stored).write_bytes(b"this is not a pcap file")

    job = _analyze_and_wait(client, capture_id)
    assert job["status"] == "failed"
    capture = client.get(f"/api/captures/{capture_id}").json()
    assert capture["status"] == "failed"

    resp = client.delete(f"/api/captures/{capture_id}")
    assert resp.status_code == 200
    _assert_all_scoped_tables_empty(capture_id)
    assert client.get(f"/api/captures/{capture_id}").status_code == 404


def test_delete_strips_case_membership(client):
    capture_id = _upload(client, "normal_traffic.pcap")
    other_id = _upload(client, "port_scan.pcap")

    case_a = client.post("/api/cases", json={"name": "Case A"}).json()
    case_b = client.post("/api/cases", json={"name": "Case B"}).json()
    client.post(f"/api/cases/{case_a['id']}/captures", json={"capture_id": capture_id})
    client.post(f"/api/cases/{case_a['id']}/captures", json={"capture_id": other_id})
    client.post(f"/api/cases/{case_b['id']}/captures", json={"capture_id": capture_id})

    resp = client.delete(f"/api/captures/{capture_id}")
    assert resp.status_code == 200

    detail_a = client.get(f"/api/cases/{case_a['id']}").json()
    detail_b = client.get(f"/api/cases/{case_b['id']}").json()
    assert capture_id not in detail_a["capture_ids"]
    assert capture_id not in detail_b["capture_ids"]
    assert other_id in detail_a["capture_ids"]  # sibling membership preserved
    assert detail_a["stats"]["capture_count"] == 1


def test_delete_rolls_back_atomically_on_db_error(client, monkeypatch):
    """A mid-transaction failure must leave EVERY row intact — no partial delete."""
    capture_id = _upload(client, "normal_traffic.pcap")
    _analyze_and_wait(client, capture_id)
    assert _count("PacketModel", capture_id) > 0

    def patched_delete_capture(self, cid):
        from sqlalchemy import delete as sa_delete

        from app.core.database import engine as _engine

        with _engine.begin() as conn:
            conn.execute(sa_delete(_orm("PacketModel")).where(_orm("PacketModel").capture_id == cid))
            raise RuntimeError("simulated failure mid-transaction")

    from app.repositories import CaptureRepository

    monkeypatch.setattr(CaptureRepository, "delete_capture", patched_delete_capture)

    resp = client.delete(f"/api/captures/{capture_id}")
    assert resp.status_code == 500

    # rollback verified: nothing was deleted
    assert client.get(f"/api/captures/{capture_id}").status_code == 200
    assert _count("PacketModel", capture_id) > 0
    assert _count("FlowModel", capture_id) > 0


def test_delete_tolerates_unlink_failure(client, monkeypatch, tmp_path):
    """If unlink fails AFTER the commit, the delete still succeeds (200)."""
    capture_id = _upload(client, "normal_traffic.pcap")
    stored = _stored_path(capture_id)

    real_unlink = Path.unlink

    def failing_unlink(self, missing_ok=False):
        if str(self) == str(stored):
            raise OSError("disk says no")
        return real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", failing_unlink)

    resp = client.delete(f"/api/captures/{capture_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["file_removed"] is False  # reported, not fatal

    # rows are gone; the file leaked (logged) — acceptable per design
    assert client.get(f"/api/captures/{capture_id}").status_code == 404
    assert Path(stored).exists()
    Path.unlink = real_unlink  # restore for fixture cleanup
    Path(stored).unlink(missing_ok=True)  # clean up test fixture file


def test_delete_never_touches_files_outside_upload_dir(client, monkeypatch, tmp_path):
    """A stored_path outside the upload dir must NOT be unlinked."""
    capture_id = _upload(client, "normal_traffic.pcap")

    # forge a stored_path pointing outside the upload dir (simulates a
    # corrupted row or a pre-migration DB)
    foreign = tmp_path / "foreign.pcap"
    foreign.write_bytes(b"another capture's evidence - must survive")
    from app.core.database import SessionLocal

    with SessionLocal() as db:
        capture = db.get(_orm("CaptureModel"), capture_id)
        capture.stored_path = str(foreign)
        db.commit()

    resp = client.delete(f"/api/captures/{capture_id}")
    assert resp.status_code == 200
    assert resp.json()["file_removed"] is False
    assert foreign.exists()  # the foreign file is intact
    assert client.get(f"/api/captures/{capture_id}").status_code == 404


def test_delete_evidence_graph_and_live_source_capture(client):
    """Graph 2.0 rows removed; live-source captures delete via the same path."""
    capture_id = _upload(client, "c2_beacon.pcap")
    _analyze_and_wait(client, capture_id)
    assert _count("GraphEdgeModel", capture_id) > 0

    # flip source to 'live' — deletion must not care about provenance
    from app.core.database import SessionLocal

    with SessionLocal() as db:
        capture = db.get(_orm("CaptureModel"), capture_id)
        capture.source = "live"
        db.commit()

    resp = client.delete(f"/api/captures/{capture_id}")
    assert resp.status_code == 200
    assert _count("GraphEdgeModel", capture_id) == 0
