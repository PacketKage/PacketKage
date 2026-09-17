"""Phase 4 tests: live capture lifecycle with a fake sniffer (no root needed).

Also includes one REAL end-to-end live test (lo interface, 4 pings) that
skips itself when sniffing isn't permitted (non-root CI).
"""

from __future__ import annotations

import time

import pytest

from app.services.live_capture import LiveCaptureError, LiveCaptureManager


class FakeSniffer:
    """Mimics the real AsyncSniffer (scapy 2.7.0) surface LiveCaptureManager uses:

    - count: running packet counter (NOT packet_counter — that attr doesn't exist)
    - exception: thread-death errors are STASHED here, not raised (scapy behavior)
    - stop(join=True): raises TypeError if called with timeout= (the bug we
      regressed against in the wild); returns the PacketList when join=True
    - join(timeout): bounded thread-join emulation
    """

    def __init__(self, interface: str, bpf: str | None, count: int = 0) -> None:
        self.iface = interface
        self.filter = bpf
        self.count = count
        self.results: list = []
        self.exception: Exception | None = None
        self.running = False
        self.started = False
        self.stopped = False
        self.start_raises: Exception | None = None

    def start(self) -> None:
        if self.start_raises:
            raise self.start_raises
        self.started = True
        self.running = True

    def stop(self, join: bool = True):
        self.stopped = True
        if join:
            return self.results
        return None

    def join(self, timeout: float | None = None) -> None:
        return None


def _make_manager(monkeypatch, interfaces=("lo", "eth0"), sniffer=None):
    sniffer = sniffer or FakeSniffer("lo", None)
    mgr = LiveCaptureManager(sniffer_factory=lambda iface, bpf, max_packets=0: sniffer)
    monkeypatch.setattr(LiveCaptureManager, "interfaces", staticmethod(lambda: list(interfaces)))
    return mgr, sniffer


# ---------------- start / status ----------------


def test_start_and_status(monkeypatch):
    mgr, sniffer = _make_manager(monkeypatch)
    status = mgr.start("lo", bpf="tcp port 80")
    assert status["status"] == "running"
    assert status["interface"] == "lo"
    assert status["bpf"] == "tcp port 80"
    assert sniffer.started
    # status is queryable and consistent
    assert mgr.status()["status"] == "running"
    mgr._cancel_watchdog()


def test_start_unknown_interface(monkeypatch):
    mgr, _ = _make_manager(monkeypatch)
    with pytest.raises(LiveCaptureError, match="not found"):
        mgr.start("wlan99")


def test_start_double_conflict(monkeypatch):
    mgr, sniffer = _make_manager(monkeypatch)
    mgr.start("lo")
    with pytest.raises(LiveCaptureError, match="already running"):
        mgr.start("eth0")
    mgr._cancel_watchdog()


def test_start_permission_error(monkeypatch):
    sniffer = FakeSniffer("lo", None)
    sniffer.start_raises = PermissionError("raw socket required")
    mgr, _ = _make_manager(monkeypatch, sniffer=sniffer)
    with pytest.raises(LiveCaptureError, match="permission"):
        mgr.start("lo")


# ---------------- stop / auto-stop ----------------


def test_stop_without_running(monkeypatch):
    mgr, _ = _make_manager(monkeypatch)
    with pytest.raises(LiveCaptureError, match="No live capture"):
        mgr.stop()


def test_stop_persists_capture_and_submits_analysis(monkeypatch, app_env):
    """Stopping must write a pcap, register a live capture, and start a job."""
    from scapy.all import IP, TCP, Ether

    sniffer = FakeSniffer("lo", None)
    sniffer.results = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2, flags="S"),
    ]
    sniffer.count = 1
    mgr, _ = _make_manager(monkeypatch, sniffer=sniffer)

    submitted: list = []
    monkeypatch.setattr(
        "app.services.jobs.job_manager",
        type("JM", (), {"submit": staticmethod(lambda *a, **k: submitted.append(a))}),
    )

    mgr.start("lo", max_seconds=600)  # long watchdog so it doesn't fire mid-test
    result = mgr.stop()

    assert result["state"]["status"] == "stopped"
    capture = result["capture"]
    assert capture["source"] == "live"
    assert capture["filename"].startswith("live_lo_")
    # pcap written into the isolated upload dir
    from pathlib import Path

    pcap_path = Path(app_env["upload_dir"]) / capture["filename"]
    assert pcap_path.exists()

    # analysis job was submitted for the new capture
    assert submitted and submitted[0][0] == capture["id"]


def test_auto_stop_fires_on_time_cap(monkeypatch, app_env):
    """The watchdog stops the capture when max_seconds elapses."""
    sniffer = FakeSniffer("lo", None)
    mgr, _ = _make_manager(monkeypatch, sniffer=sniffer)
    submitted = []
    monkeypatch.setattr(
        "app.services.jobs.job_manager",
        type("JM", (), {"submit": staticmethod(lambda *a, **k: submitted.append(a))}),
    )
    mgr.start("lo", max_seconds=1)
    deadline = time.time() + 5
    while time.time() < deadline and mgr.status()["status"] == "running":
        time.sleep(0.1)
    assert mgr.status()["status"] == "stopped", "watchdog must auto-stop the capture"


# ---------------- API surface ----------------


def test_live_api_endpoints(monkeypatch, client):
    """Full HTTP lifecycle over the router with a fake sniffer.

    NOTE: the client fixture reimports app modules (conftest purge), so all
    patches must resolve classes/managers from the CURRENT modules at run time.
    """
    import app.services.live_capture as lc_mod  # the module the running app uses

    sniffer = FakeSniffer("lo", None)
    fresh_manager = lc_mod.LiveCaptureManager(sniffer_factory=lambda i, b, max_packets=0: sniffer)
    import app.api.live as live_mod

    monkeypatch.setattr(live_mod, "live_manager", fresh_manager)
    monkeypatch.setattr(lc_mod.LiveCaptureManager, "interfaces", staticmethod(lambda: ["lo"]))

    # interfaces listing
    ifaces = client.get("/api/live/interfaces").json()
    assert isinstance(ifaces, list)

    # start
    resp = client.post("/api/live/start", json={"interface": "lo", "bpf": "tcp"})
    assert resp.status_code == 202, resp.text
    assert resp.json()["status"] == "running"

    # double start → 409
    resp = client.post("/api/live/start", json={"interface": "lo"})
    assert resp.status_code == 409

    # status
    status = client.get("/api/live/status").json()
    assert status["status"] == "running"
    assert status["interface"] == "lo"

    # stop → capture registered
    monkeypatch.setattr(
        "app.services.jobs.job_manager",
        type("JM", (), {"submit": staticmethod(lambda *a, **k: None)}),
    )
    resp = client.post("/api/live/stop")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["state"]["status"] == "stopped"
    assert body["capture"]["source"] == "live"

    # stop again → 409
    resp = client.post("/api/live/stop")
    assert resp.status_code == 409


def test_live_api_bad_interface(client):
    resp = client.post("/api/live/start", json={"interface": "doesnotexist0"})
    assert resp.status_code == 400
    assert "not found" in resp.json()["detail"]


# ---------------- stashed-exception paths (scapy thread deaths) ----------------


def test_start_fails_fast_on_stashed_permission_error(monkeypatch):
    """The user's bug: socket open fails on the sniffing thread with
    [Errno 1] Operation not permitted; scapy STASHES it in .exception.
    start() must fail immediately with the friendly permission message."""

    class DiesAfterStart(FakeSniffer):
        def start(self) -> None:
            super().start()
            # emulate the sniffing thread dying right away (scapy never raises)
            self.running = True
            self.exception = OSError(1, "Operation not permitted")

    dying = DiesAfterStart("lo", None)
    mgr, _ = _make_manager(monkeypatch, sniffer=dying)
    with pytest.raises(LiveCaptureError, match="Insufficient permissions"):
        mgr.start("lo")
    # no state left behind — a failed start must be retryable
    assert mgr.status() is None or mgr.status()["status"] != "running"


def test_status_flips_to_failed_when_sniffer_dies_mid_run(monkeypatch):
    """Sniffer dies mid-capture → next status() poll reports failed + reason."""
    sniffer = FakeSniffer("lo", None)
    mgr, _ = _make_manager(monkeypatch, sniffer=sniffer)
    mgr.start("lo", max_seconds=600)

    # thread dies mid-capture — scapy stashes the error, sets nothing else
    sniffer.exception = OSError(1, "Operation not permitted")
    status = mgr.status()
    assert status["status"] == "failed"
    assert "Insufficient permissions" in status["error"]
    # subsequent stops get the clear message, not "failed to stop sniffer cleanly"
    with pytest.raises(LiveCaptureError, match="No live capture is running"):
        mgr.stop()


def test_stop_reports_stashed_error_with_clear_message(monkeypatch, app_env):
    """Stop on a dead sniffer with no packets: clear permission message,
    not the misleading 'failed to stop sniffer cleanly: [Errno 1]'."""

    class DiesOnStop(FakeSniffer):
        def stop(self, join: bool = True):
            # emulate: stop() re-raises the stashed thread exception (scapy
            # raises self.exception from stop/join when the thread died)
            raise self.exception  # noqa: TRY001

    dies = DiesOnStop("lo", None)
    mgr, _ = _make_manager(monkeypatch, sniffer=dies)
    mgr.start("lo", max_seconds=600)
    dies.exception = OSError(1, "Operation not permitted")

    with pytest.raises(LiveCaptureError, match="Insufficient permissions"):
        mgr.stop()
    assert mgr.status()["status"] == "failed"


def test_stop_salvages_packets_from_dead_sniffer(monkeypatch, app_env):
    """Thread died late in the capture — recorded packets are still evidence:
    stop() must persist them, not discard the whole recording."""
    from scapy.all import IP, TCP, Ether

    died = FakeSniffer("lo", None)
    died.results = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2, flags="S"),
    ]
    died.count = 1

    died.stop = lambda join=True: (_ for _ in ()).throw(died.exception)  # type: ignore[method-assign]
    mgr, _ = _make_manager(monkeypatch, sniffer=died)

    submitted: list = []
    monkeypatch.setattr(
        "app.services.jobs.job_manager",
        type("JM", (), {"submit": staticmethod(lambda *a, **k: submitted.append(a))}),
    )
    mgr.start("lo", max_seconds=600)
    died.exception = OSError(1, "Operation not permitted")

    result = mgr.stop()
    assert result["state"]["status"] == "stopped"
    assert result["capture"]["source"] == "live"
    assert submitted, "salvaged packets must still be analyzed"


# ---------------- Real sniffing integration (root only) ----------------


def test_real_live_capture_lo():
    """End-to-end on the loopback interface — skipped without sniffing privileges."""
    import socket

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 3)
        s.close()
    except PermissionError:
        pytest.skip("live sniffing requires root/CAP_NET_RAW")

    from scapy.all import ICMP, IP, sr1

    mgr = LiveCaptureManager()
    if "lo" not in mgr.interfaces():
        pytest.skip("no loopback interface")

    mgr.start("lo", bpf="icmp", max_seconds=30)
    try:
        sr1(IP(dst="127.0.0.1") / ICMP(), timeout=4, verbose=0)
    finally:
        result = mgr.stop()

    assert result["state"]["status"] == "stopped"
    assert result["state"]["packet_count"] >= 1, "expected to capture the loopback ping"
    assert result["capture"]["source"] == "live"


def test_scapy_stop_signature_compat():
    """Guard: the real AsyncSniffer.stop() must accept the kwargs we call it with.

    The original live-capture bug (stop(timeout=5) TypeError) shipped because
    the FakeSniffer mirrored the wrong API. This checks the REAL scapy class.
    """
    import inspect

    from scapy.all import AsyncSniffer

    params = inspect.signature(AsyncSniffer.stop).parameters
    assert "join" in params, f"scapy stop() signature changed: {list(params)}"
    assert "timeout" not in params, "scapy added a timeout kwarg — revisit stop() call"
    # join() must accept a timeout bound (we rely on it for the 5s cap)
    join_params = inspect.signature(AsyncSniffer.join).parameters
    assert len(join_params) >= 1, f"AsyncSniffer.join no longer accepts args: {join_params}"


def test_fake_sniffer_mirrors_real_surface():
    """The fake must keep mirroring the real sniffer's used API surface."""
    import inspect

    from scapy.all import AsyncSniffer

    real_stop = inspect.signature(AsyncSniffer.stop).parameters
    fake_stop = inspect.signature(FakeSniffer.stop).parameters
    assert set(fake_stop) == set(real_stop), (
        f"FakeSniffer.stop {list(fake_stop)} drifted from AsyncSniffer.stop {list(real_stop)}"
    )
    for attr in ("count", "results", "start", "join"):
        assert hasattr(FakeSniffer("lo", None), attr) or attr in FakeSniffer.__dict__


def test_start_passes_max_packets_to_sniffer(monkeypatch):
    """The packet cap must reach the sniffer factory so AsyncSniffer's native
    count-based auto-stop enforces it (previously only max_seconds worked)."""
    captured_kwargs: list = []

    def factory(iface, bpf, max_packets=0):
        captured_kwargs.append((iface, bpf, max_packets))
        sniffer = FakeSniffer(iface, bpf)
        return sniffer

    mgr = LiveCaptureManager(sniffer_factory=factory)
    monkeypatch.setattr(LiveCaptureManager, "interfaces", staticmethod(lambda: ["lo"]))
    mgr.start("lo", bpf="tcp", max_packets=12345, max_seconds=600)
    assert captured_kwargs == [("lo", "tcp", 12345)]
    mgr._cancel_watchdog()


def test_default_sniffer_receives_count(monkeypatch):
    """The real AsyncSniffer must be constructed with count=max_packets.

    The class and the patched global are taken from the SAME module object —
    conftest purges app.* modules between tests, so patching by string can
    hit a different (reloaded) module than the one the imported class uses.
    """
    from unittest.mock import MagicMock

    import app.services.live_capture as lc

    sniffer_cls = MagicMock()
    monkeypatch.setattr(lc, "AsyncSniffer", sniffer_cls)

    lc.LiveCaptureManager._default_sniffer("lo", "tcp port 80", 5000)
    sniffer_cls.assert_called_once_with(iface="lo", filter="tcp port 80", store=True, count=5000)

    sniffer_cls.reset_mock()
    # zero/None caps mean unlimited
    lc.LiveCaptureManager._default_sniffer("lo", None, 0)
    sniffer_cls.assert_called_once_with(iface="lo", filter=None, store=True, count=0)
