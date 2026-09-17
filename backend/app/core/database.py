"""SQLAlchemy engine/session management (SQLite first, extensible later)."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Generator
from typing import Any

from sqlalchemy import create_engine, event
from sqlalchemy import exc as sa_exc
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    pass


# ---- SQLite lock retry (audit C2) ------------------------------------------
# The analysis jobs, the SSE poller and the API share one SQLite file. WAL +
# busy_timeout covers most contention, but a big batch commit (e.g. 5k-packet
# persist) can exceed the 5s busy timeout; the loser then dies with
# "database is locked" mid-transaction and the capture is spuriously marked
# failed. RetryingSession replays the pending unit of work after rollback
# (empirically verified: rollback clears the new/dirty/deleted sets, and
# re-setattr/add/delete via the public API re-instruments everything).

_LOCK_RETRY_ATTEMPTS = 4
_LOCK_RETRY_BACKOFF = (0.05, 0.2, 0.8)  # seconds between attempts


def _is_lock_error(exc: BaseException) -> bool:
    return isinstance(exc, sa_exc.OperationalError) and "database is locked" in str(exc)


def _snapshot_pending(session: Session) -> tuple[list, dict[int, dict], set[int]]:
    """Capture the pending unit of work BEFORE a commit attempt.

    Key detail: a failed commit() rolls the session back internally, so
    new/dirty/deleted are ALREADY empty by the time the error surfaces.
    Snapshotting must happen before the attempt, not in the except handler.

    Returns (pinned, attrs, deleted_ids) — the caller keeps `pinned` alive so
    the id() keys stay valid; objects are re-instrumented via the public API
    (setattr/add/delete) after our rollback.
    """
    pinned = list(session.new | session.dirty | session.deleted)
    attrs: dict[int, dict] = {}
    for obj in session.new | session.dirty:
        attrs[id(obj)] = {k: v for k, v in obj.__dict__.items() if not k.startswith("_sa_")}
    deleted_ids = {id(o) for o in session.deleted}
    return pinned, attrs, deleted_ids


def _replay_pending(session: Session, pinned: list, attrs: dict[int, dict], deleted_ids: set[int]) -> None:
    """Re-apply a snapshotted unit of work after a rollback.

    deletes → re-delete (merge back if detached); new → re-add;
    dirty → setattr re-dirties instrumented attributes.
    """
    for obj in pinned:
        st = sa_inspect(obj)
        if id(obj) in deleted_ids:
            target = session.merge(obj, load=False) if st.detached else obj
            session.delete(target)
        else:
            for k, v in attrs.get(id(obj), {}).items():
                setattr(obj, k, v)  # public api → marks dirty again
            if not st.persistent:
                session.add(obj)


class RetryingSession(Session):
    """Session whose commit()/flush() survive transient SQLite lock contention.

    On "database is locked": snapshot the pending unit of work, rollback
    (which clears new/dirty/deleted), replay it via the public API, and retry
    after a short backoff. Non-lock errors propagate unchanged.
    """

    # commit() routes through the public flush(); a retry there would call
    # rollback() mid-commit (IllegalStateChangeError), so commit's own retry
    # loop owns recovery and flush() runs plain while this flag is set.
    _in_commit = False

    def _retry_loop(self, operation: Callable[[], Any]) -> Any:
        attempt = 0
        while True:
            # Snapshot BEFORE the attempt — a failed commit clears the
            # pending sets before the exception surfaces.
            pinned, attrs, deleted_ids = _snapshot_pending(self)
            try:
                return operation()
            except sa_exc.OperationalError as exc:
                if not _is_lock_error(exc) or attempt >= _LOCK_RETRY_ATTEMPTS - 1:
                    raise
                attempt += 1

                self.rollback()  # clears new/dirty/deleted, expires instances
                _replay_pending(self, pinned, attrs, deleted_ids)

                time.sleep(_LOCK_RETRY_BACKOFF[min(attempt - 1, len(_LOCK_RETRY_BACKOFF) - 1)])

    def commit(self) -> None:
        self._in_commit = True
        try:
            self._retry_loop(super().commit)
        finally:
            self._in_commit = False

    def flush(self) -> None:
        if self._in_commit:
            super().flush()  # commit's retry loop owns lock recovery
            return
        self._retry_loop(super().flush)


def _fk_pragma_on_connect(dbapi_con, _con_record):  # SQLite FK enforcement + WAL
    if hasattr(dbapi_con, "execute"):
        dbapi_con.execute("pragma foreign_keys=ON")
        dbapi_con.execute("pragma journal_mode=WAL")  # concurrent reads during job writes
        dbapi_con.execute("pragma busy_timeout=5000")  # ms to wait for locks instead of failing


def make_engine(url: str | None = None) -> Engine:
    url = url or settings.database_url
    engine = create_engine(
        url,
        connect_args={"check_same_thread": False} if url.startswith("sqlite") else {},
    )
    if url.startswith("sqlite"):
        event.listen(engine, "connect", _fk_pragma_on_connect)
    return engine


engine = make_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, class_=RetryingSession)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def new_id() -> str:
    return uuid.uuid4().hex
