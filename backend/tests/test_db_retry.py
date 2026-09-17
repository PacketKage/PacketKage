"""RetryingSession: commit survives transient SQLite write-lock contention.

Uses a dedicated engine with a short busy_timeout so "database is locked"
fails fast (deterministic) instead of the production 5s wait. The lock is
held by a raw sqlite3 connection doing BEGIN IMMEDIATE — with WAL enabled
readers still work, only writers block, mirroring production semantics.
"""

from __future__ import annotations

import sqlite3
import tempfile
import threading
import time
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from app.core.database import RetryingSession


class _RetryBase(DeclarativeBase):
    pass


class RetryRow(_RetryBase):
    __tablename__ = "retry_rows"

    id: Mapped[int] = mapped_column(primary_key=True)
    v: Mapped[int] = mapped_column(sa.Integer, default=0)
    name: Mapped[str] = mapped_column(sa.String(32), default="x")


@pytest.fixture()
def retry_env():
    """Engine with WAL + 20ms busy_timeout (fails fast), RetryingSession bound."""
    tmpdir = tempfile.mkdtemp(prefix="retrydb_")
    db_path = Path(tmpdir) / "retry.db"
    eng = sa.create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})

    @sa.event.listens_for(eng, "connect")
    def _pragmas(dbapi_con, _):  # pragma: no cover - mirror production pragmas
        dbapi_con.execute("pragma foreign_keys=ON")
        dbapi_con.execute("pragma journal_mode=WAL")
        dbapi_con.execute("pragma busy_timeout=20")  # ms — fail fast, like a >5s stall

    _RetryBase.metadata.create_all(eng)
    factory = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False, class_=RetryingSession)
    yield {"engine": eng, "factory": factory, "db_path": db_path}
    eng.dispose()


def _seed(factory) -> None:
    s = factory()
    s.add(RetryRow(id=1, v=0, name="orig"))
    s.add(RetryRow(id=3, v=0, name="gone"))
    s.commit()
    s.close()


def _hold_lock_for(db_path: Path, duration: float) -> threading.Thread:
    """Hold the write lock in a background thread, release automatically.

    sqlite3 connections are thread-bound (created and used in the same
    thread), so the whole hold-release cycle runs inside the thread.
    """
    ready = threading.Event()

    def run() -> None:
        conn = sqlite3.connect(str(db_path), timeout=0.02)
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE retry_rows SET v = v + 1 WHERE id = 3")
        ready.set()
        time.sleep(duration)
        conn.rollback()
        conn.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    ready.wait(timeout=5)
    return t


def test_commit_retries_under_lock(retry_env):
    """A held write lock + later release → commit succeeds via retry."""
    _seed(retry_env["factory"])
    _hold_lock_for(retry_env["db_path"], duration=0.15)

    s = retry_env["factory"]()
    try:
        s.add(RetryRow(id=2, v=7, name="new"))
        s.commit()
    finally:
        s.close()

    check = retry_env["factory"]()
    row = check.get(RetryRow, 2)
    assert row is not None and row.v == 7
    check.close()


def test_full_unit_of_work_replayed_after_retry(retry_env):
    """Update + insert + delete are ALL re-applied after a lock-failed commit."""
    _seed(retry_env["factory"])
    _hold_lock_for(retry_env["db_path"], duration=0.15)

    s = retry_env["factory"]()
    try:
        # full unit of work: update + insert + delete
        r1 = s.get(RetryRow, 1)
        assert r1 is not None
        r1.v = 42
        r1.name = "changed"
        s.add(RetryRow(id=2, v=7, name="new"))
        gone = s.get(RetryRow, 3)
        assert gone is not None
        s.delete(gone)
        s.commit()
    finally:
        s.close()

    check = retry_env["factory"]()
    try:
        r1 = check.get(RetryRow, 1)
        assert r1 is not None
        assert r1.v == 42 and r1.name == "changed"
        r2 = check.get(RetryRow, 2)
        assert r2 is not None and r2.v == 7
        assert check.get(RetryRow, 3) is None
    finally:
        check.close()


def test_gives_up_after_max_attempts(retry_env):
    """Lock never released → OperationalError propagates after all attempts."""
    _seed(retry_env["factory"])
    _hold_lock_for(retry_env["db_path"], duration=10.0)  # outlives the retry window

    s = retry_env["factory"]()
    try:
        with pytest.raises(sa.exc.OperationalError) as excinfo:
            s.add(RetryRow(id=2, v=1, name="never"))
            s.commit()
        assert "database is locked" in str(excinfo.value) or "locked" in str(excinfo.value)
    finally:
        s.close()


def test_non_lock_errors_propagate_unchanged(retry_env):
    """Integrity errors (e.g. PK collision) must NOT be retried or swallowed."""
    _seed(retry_env["factory"])
    s = retry_env["factory"]()
    try:
        with pytest.raises(sa.exc.IntegrityError):
            s.add(RetryRow(id=1, v=9, name="dup"))  # PK conflict
            s.commit()
    finally:
        s.close()


def test_concurrent_sessions_both_commit(retry_env):
    """Two threads, separate sessions, shared engine — contention resolves via retry."""
    factory = retry_env["factory"]
    _seed(factory)

    errors: list[str] = []

    def worker(n: int) -> None:
        try:
            s = factory()
            try:
                for i in range(10):
                    s.add(RetryRow(id=100 + n * 100 + i, v=i, name=f"w{n}"))
                    s.commit()  # separate unit per row → frequent write contention
            finally:
                s.close()
        except Exception as exc:  # pragma: no cover - failure reporter
            errors.append(f"{n}: {exc!r}")

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert errors == []
    check = factory()
    try:
        count = check.query(RetryRow).filter(RetryRow.id >= 100).count()
        assert count == 20
    finally:
        check.close()
