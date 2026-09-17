"""Shared API helpers."""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.db.orm import CaptureModel


def capture_or_404(db: Session, capture_id: str) -> CaptureModel:
    capture = db.get(CaptureModel, capture_id)
    if capture is None:
        raise HTTPException(404, "Capture not found")
    return capture
