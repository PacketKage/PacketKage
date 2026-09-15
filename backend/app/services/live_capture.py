"""Live capture — AsyncSniffer-based interface recording.

Lifecycle:
    start(interface, bpf, max_packets, max_seconds)
        → sniffer thread records packets into an in-memory list
        → auto-stop watchdog (packet count / time cap)
    stop()
        → writes recorded packets to a PCAP in the upload dir
        → registers it as a Capture(source="live")
        → submits the normal background analysis job
        → the capture then flows through the standard pipeline
          (flows/hosts/alerts/timeline), fully reusing the upload path.

No privileges required to *list* interfaces; actually sniffing needs root
(or capabilities) and surfaces a clean error message when it fails.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from scapy.all import AsyncSniffer
from scapy.interfaces import get_if_list


class LiveCaptureError(Exception):
    """User-facing live-capture errors (bad interface, permissions, wrong state)."""


@dataclass
class LiveState:
    interface: str
    bpf: str | None
    max_packets: int
    max_seconds: int
    started_at: float = field(default_factory=time.time)
    stopped_at: float | None = None
    status: str = "running"  # running | stopped | failed
    error: str | None = None
    final_packet_count: int | None = None  # frozen at stop() — sniffer is nulled


class LiveCaptureManager:
    """Manages at most one active live capture (single-user, local tool)."""

    def __init__(self, sniffer_factory=None) -> None:
        # sniffer_factory is injectable for tests (no real sniffing)
        self._sniffer_factory = sniffer_factory or self._default_sniffer
        self._lock = threading.RLock()  # reentrant: start() holds lock while reading status()
        self._sniffer = None
        self._watchdog: threading.Timer | None = None
        self.state: LiveState | None = None

    @staticmethod
    def _default_sniffer(interface: str, bpf: str | None, max_packets: int = 0):
        # count=0 means "no limit" in scapy; a positive count auto-stops the
        # sniffer once reached, enforcing the packet cap natively.
        return AsyncSniffer(
            iface=interface, filter=bpf, store=True,
            count=max_packets if max_packets and max_packets > 0 else 0,
        )

    # ---------------- introspection ----------------

    @staticmethod
    def interfaces() -> list[str]:
        try:
            return list(get_if_list())
        except Exception:
            return []

    def _cancel_watchdog(self) -> None:
        if self._watchdog is not None:
            self._watchdog.cancel()
            self._watchdog = None

    def status(self) -> dict | None:
        with self._lock:
            if self.state is None:
                return None
            s = self.state
            # A dead sniffer thread (permissions dropped mid-run, socket error)
            # must surface as failed on the next poll — not "running" forever.
            if s.status == "running" and self._sniffer is not None:
                exc = self._exception_of(self._sniffer)
                if exc is not None:
                    s.status = "failed"
                    s.error = self._friendly_sniff_error(exc)
                    self._sniffer = None
                    self._cancel_watchdog()
            packet_count = self._current_packet_count()
            elapsed = (s.stopped_at or time.time()) - s.started_at
            return {
                "status": s.status,
                "interface": s.interface,
                "bpf": s.bpf,
                "packet_count": packet_count,
                "elapsed_seconds": round(elapsed, 1),
                "max_packets": s.max_packets,
                "max_seconds": s.max_seconds,
                "error": s.error,
            }

    def _current_packet_count(self) -> int:
        s = self.state
        if s is not None and s.final_packet_count is not None:
            return s.final_packet_count  # terminal: frozen count from stop()
        sniffer = self._sniffer
        if sniffer is None:
            return 0
        # scapy 2.7.0 AsyncSniffer counts in `.count`; fall back to the
        # recorded results list for custom/fake sniffers that don't.
        return int(getattr(sniffer, "count", 0)) or len(
            getattr(sniffer, "results", None) or []
        )

    # ---------------- lifecycle ----------------

    @staticmethod
    def _friendly_sniff_error(exc: BaseException) -> str:
        """Map low-level sniffing failures to actionable messages."""
        msg = str(exc)
        if "Operation not permitted" in msg or "Errno 1" in msg or isinstance(exc, PermissionError):
            return (
                "Insufficient permissions to sniff — run the backend as root "
                "or grant CAP_NET_RAW / CAP_NET_ADMIN (e.g. "
                "sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python)))"
            )
        return f"Sniffer failed: {msg}"

    @staticmethod
    def _exception_of(sniffer) -> BaseException | None:
        """scapy's AsyncSniffer stashes thread-death errors in `.exception`."""
        exc = getattr(sniffer, "exception", None)
        return exc if isinstance(exc, BaseException) else None

    def start(
        self,
        interface: str,
        bpf: str | None = None,
        max_packets: int = 100_000,
        max_seconds: int = 300,
    ) -> dict:
        with self._lock:
            if self.state is not None and self.state.status == "running":
                raise LiveCaptureError(
                    f"A live capture is already running on {self.state.interface} — stop it first"
                )
            if interface not in self.interfaces():
                raise LiveCaptureError(
                    f"Interface {interface!r} not found on this system"
                )

            sniffer = self._sniffer_factory(interface, bpf, max_packets)
            try:
                sniffer.start()
            except PermissionError:
                raise LiveCaptureError(
                    "Insufficient permissions to sniff — run the backend as root "
                    "or grant CAP_NET_RAW / CAP_NET_ADMIN"
                ) from None
            except Exception as exc:
                raise LiveCaptureError(f"Could not start sniffer: {exc}") from exc

            # scapy opens the raw socket on the sniffing thread and records a
            # failure there (e.g. [Errno 1] Operation not permitted) in
            # `sniffer.exception` WITHOUT raising from start(). Poll briefly
            # so permission problems fail here with a clear message instead
            # of "running" for the whole duration and exploding at stop().
            #
            # The poll also doubles as an attach grace period: scapy flips
            # its `running` flag before the raw socket is fully attached, so
            # traffic sent in the first ~0.5s can be missed (observed in
            # containers). Waiting the full 0.75s window closes that race —
            # `running`-early-break is NOT used on purpose.
            deadline = time.monotonic() + 0.75
            while time.monotonic() < deadline:
                exc = self._exception_of(sniffer)
                if exc is not None:
                    raise LiveCaptureError(self._friendly_sniff_error(exc)) from exc
                time.sleep(0.05)
            exc = self._exception_of(sniffer)
            if exc is not None:
                raise LiveCaptureError(self._friendly_sniff_error(exc)) from exc

            self._sniffer = sniffer
            self.state = LiveState(
                interface=interface,
                bpf=bpf,
                max_packets=max_packets,
                max_seconds=max_seconds,
            )

            # auto-stop watchdog: whichever cap is hit first
            self._watchdog = threading.Timer(max_seconds, self._auto_stop)
            self._watchdog.daemon = True
            self._watchdog.start()
            return self.status()

    def _auto_stop(self) -> None:
        import contextlib

        with contextlib.suppress(Exception):  # a concurrent manual stop already finished us
            self.stop()

    def stop(self) -> dict:
        """Stop recording, persist the PCAP, and kick off analysis."""
        with self._lock:
            s = self.state
            sniffer = self._sniffer
            if s is None or s.status != "running" or sniffer is None:
                raise LiveCaptureError("No live capture is running")
            self._cancel_watchdog()

            packets = []
            try:
                # The sniffing thread may have died earlier with a stashed
                # error (permissions, socket failure) — surface it with a
                # clear message instead of a misleading "stop failed".
                stashed = self._exception_of(sniffer)
                if stashed is not None:
                    packets = list(getattr(sniffer, "results", None) or [])
                    if not packets:
                        s.status = "failed"
                        s.error = self._friendly_sniff_error(stashed)
                        self._sniffer = None
                        raise LiveCaptureError(s.error) from stashed
                    # thread died late — whatever it recorded is still evidence
                else:
                    # scapy 2.7.0: stop(join=True) blocks in the socket read until the
                    # next packet arrives — potentially forever on a quiet interface.
                    # Detach first, then bound the thread join to 5s so Stop always
                    # returns. Packets recorded before the detach are still collected.
                    sniffer.stop(join=False)
                    sniffer.join(5)
                    packets = list(getattr(sniffer, "results", None) or [])
            except LiveCaptureError:
                raise
            except Exception as exc:
                # The recording itself may still be salvageable — persist what
                # we have instead of discarding everything on a stop hiccup.
                packets = list(getattr(sniffer, "results", None) or [])
                if not packets:
                    s.status = "failed"
                    s.error = f"failed to stop sniffer cleanly: {exc}"
                    raise LiveCaptureError(s.error) from exc
            finally:
                self._sniffer = None

            s.status = "stopped"
            s.stopped_at = time.time()
            # Freeze the count on the state BEFORE the sniffer is nulled —
            # status() derives packet_count from the sniffer while running,
            # but self._sniffer is already None by the time it is next read.
            s.final_packet_count = len(packets)

        capture = self._persist(packets, s)
        return {"state": self.status(), "capture": capture}

    # ---------------- persistence ----------------

    def _persist(self, packets: list, state: LiveState) -> dict:
        # ALL app imports deferred to avoid import cycles under the test
        # conftest's module-purge reload pattern (app.services.jobs pulls the
        # whole analysis pipeline; keeping this module import-light prevents
        # partially-initialized-module deadlocks)
        from scapy.all import wrpcap

        from app.core.config import settings
        from app.core.database import SessionLocal
        from app.repositories import CaptureRepository
        from app.services.jobs import job_manager

        settings.ensure_dirs()
        filename = f"live_{state.interface.replace('/', '_')}_{int(state.started_at)}.pcap"
        dest = settings.upload_dir / filename
        try:
            wrpcap(str(dest), packets)
        except Exception as exc:
            raise LiveCaptureError(f"Failed to write capture file: {exc}") from exc

        db = SessionLocal()
        try:
            repo = CaptureRepository(db)
            capture = repo.create(
                filename=filename, source="live", size_bytes=dest.stat().st_size
            )
            capture = repo.update(capture, stored_path=str(dest))
            cap_id, stored = capture.id, str(dest)
            job_manager.submit(cap_id, _create_and_get_job(db, cap_id).id, stored, None)
            return {
                "id": cap_id,
                "filename": filename,
                "source": "live",
                "status": capture.status,
            }
        finally:
            db.close()


def _create_and_get_job(db, capture_id: str):
    from app.repositories import JobRepository

    return JobRepository(db).create(capture_id)


# module-level singleton (tests construct their own with a fake factory)
live_manager = LiveCaptureManager()
