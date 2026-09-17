"""Live capture endpoints: interface listing, start/status/stop."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.live_capture import LiveCaptureError, live_manager

router = APIRouter(prefix="/api/live", tags=["live"])


@router.get("/interfaces", response_model=list[str])
def list_interfaces():
    """Network interfaces available for live capture."""
    return live_manager.interfaces()


class LiveStartRequest(BaseModel):
    interface: str
    bpf: str | None = Field(default=None, max_length=500)
    max_packets: int = Field(default=100_000, ge=1, le=1_000_000)
    max_seconds: int = Field(default=300, ge=1, le=86_400)


@router.post("/start", status_code=202)
def start_live(body: LiveStartRequest):
    """Start recording on an interface. Only one live capture may run at a time."""
    try:
        return live_manager.start(
            interface=body.interface,
            bpf=body.bpf or None,
            max_packets=body.max_packets,
            max_seconds=body.max_seconds,
        )
    except LiveCaptureError as exc:
        # running/permissions/bad interface — client-actionable messages
        code = 409 if "already running" in str(exc) else 400
        raise HTTPException(code, str(exc)) from exc


@router.get("/status")
def live_status():
    """Current live capture state (null when idle)."""
    return live_manager.status()


@router.post("/stop")
def stop_live():
    """Stop recording, persist the PCAP, and start analysis (returns new capture)."""
    try:
        return live_manager.stop()
    except LiveCaptureError as exc:
        raise HTTPException(409, str(exc)) from exc
