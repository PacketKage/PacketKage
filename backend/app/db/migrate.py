"""Lightweight SQLite schema migration.

`Base.metadata.create_all` only creates MISSING TABLES — it never alters
existing ones. This helper adds any missing COLUMNS to existing tables so
older local databases keep working across upgrades (dev-tool friendly,
no Alembic needed at this scale).
"""

from __future__ import annotations

import sqlite3

from app.db.orm import AlertModel

# column -> DDL for columns added after the first release
MIGRATIONS: dict[str, dict[str, str]] = {
    AlertModel.__tablename__: {
        "tags": "JSON DEFAULT '[]'",
        "note": "TEXT",
    },
}


def run_migrations(db_path: str) -> int:
    """Add missing columns to existing SQLite tables. Returns count applied."""
    applied = 0
    conn = sqlite3.connect(db_path)
    try:
        for table, columns in MIGRATIONS.items():
            existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
            if not existing:
                continue  # table not created yet; create_all handles it with full schema
            for column, ddl in columns.items():
                if column not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
                    applied += 1
        conn.commit()
    finally:
        conn.close()
    return applied


def _default_db_path() -> str | None:
    from app.core.config import settings

    url = settings.database_url
    if not url.startswith("sqlite:///"):
        return None
    return url.replace("sqlite:///", "", 1)


def migrate_if_sqlite() -> None:
    """Run column migrations against the configured SQLite DB (no-op otherwise)."""
    path = _default_db_path()
    if path is None:
        return
    import os

    if not os.path.exists(path):
        return  # fresh DB: create_all builds the full schema
    run_migrations(path)
