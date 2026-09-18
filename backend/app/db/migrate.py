"""Lightweight SQLite schema migration.

`Base.metadata.create_all` only creates MISSING TABLES — it never alters
existing ones. This helper adds any missing COLUMNS to existing tables so
older local databases keep working across upgrades (dev-tool friendly,
no Alembic needed at this scale).
"""

from __future__ import annotations

import re
import sqlite3

from app.db.orm import AlertModel

_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_ALLOWED_DDL_RE = re.compile(
    r"^(?:TEXT|VARCHAR\(\d+\)|INTEGER|BOOLEAN|FLOAT|DATETIME|JSON)(?:\s+DEFAULT\s+(?:'[^']*'|\d+|NULL|TRUE|FALSE))?$",
    re.IGNORECASE,
)


def _validate_identifier(name: str) -> str:
    """Validate and double-quote a SQL table or column identifier."""
    if not isinstance(name, str) or not _IDENTIFIER_RE.match(name):
        raise ValueError(f"Invalid SQL identifier: {name!r}")
    return f'"{name}"'


def _validate_ddl(ddl: str) -> str:
    """Validate that a column DDL snippet matches safe data-type and default patterns."""
    if not isinstance(ddl, str) or not _ALLOWED_DDL_RE.match(ddl.strip()):
        raise ValueError(f"Invalid or unsupported column DDL: {ddl!r}")
    return ddl.strip()


# column -> DDL for columns added after the first release
MIGRATIONS: dict[str, dict[str, str]] = {
    AlertModel.__tablename__: {
        "tags": "JSON DEFAULT '[]'",
        "note": "TEXT",
        "title_key": "VARCHAR(128)",
        "title_params": "JSON DEFAULT '{}'",
        "explanation_key": "VARCHAR(128)",
        "explanation_params": "JSON DEFAULT '{}'",
    },
}


def run_migrations(db_path: str) -> int:
    """Add missing columns to existing SQLite tables. Returns count applied."""
    applied = 0
    conn = sqlite3.connect(db_path)
    try:
        for table, columns in MIGRATIONS.items():
            quoted_table = _validate_identifier(table)
            existing = {row[1] for row in conn.execute(f"PRAGMA table_info({quoted_table})")}
            if not existing:
                continue  # table not created yet; create_all handles it with full schema
            for column, ddl in columns.items():
                if column not in existing:
                    quoted_col = _validate_identifier(column)
                    safe_ddl = _validate_ddl(ddl)
                    conn.execute(f"ALTER TABLE {quoted_table} ADD COLUMN {quoted_col} {safe_ddl}")
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
