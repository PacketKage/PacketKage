"""Tests for database migration identifier and DDL sanitization."""

from __future__ import annotations

import sqlite3

import pytest

from app.db.migrate import (
    _validate_ddl,
    _validate_identifier,
    run_migrations,
)


def test_validate_identifier_valid():
    assert _validate_identifier("alerts") == '"alerts"'
    assert _validate_identifier("custom_col_123") == '"custom_col_123"'
    assert _validate_identifier("_internal") == '"_internal"'


def test_validate_identifier_invalid():
    invalid_names = [
        "alerts; DROP TABLE users; --",
        "alerts' OR '1'='1",
        "123start_with_number",
        "col name with spaces",
        "col-with-dashes",
        "",
    ]
    for name in invalid_names:
        with pytest.raises(ValueError):
            _validate_identifier(name)


def test_validate_ddl_valid():
    valid_ddls = [
        "JSON DEFAULT '[]'",
        "TEXT",
        "VARCHAR(128)",
        "JSON DEFAULT '{}'",
        "INTEGER DEFAULT 0",
        "BOOLEAN DEFAULT TRUE",
        "FLOAT DEFAULT NULL",
    ]
    for ddl in valid_ddls:
        assert _validate_ddl(ddl) == ddl


def test_validate_ddl_invalid():
    invalid_ddls = [
        "TEXT; DROP TABLE alerts; --",
        "JSON DEFAULT '''; DROP TABLE alerts; --'",
        "VARCHAR(128) PRIMARY KEY",
        "MALICIOUS_TYPE",
        "",
    ]
    for ddl in invalid_ddls:
        with pytest.raises(ValueError):
            _validate_ddl(ddl)


def test_run_migrations_adds_missing_columns(tmp_path):
    db_file = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_file))
    # Create legacy schema without tags, note, title_key, etc.
    conn.execute(
        """
        CREATE TABLE alerts (
            id VARCHAR(64) PRIMARY KEY,
            capture_id VARCHAR(64),
            rule_id VARCHAR(64),
            severity VARCHAR(16),
            title TEXT
        )
        """
    )
    conn.commit()
    conn.close()

    applied = run_migrations(str(db_file))
    assert applied == 6

    # Re-running migrations should be idempotent (0 applied)
    assert run_migrations(str(db_file)) == 0

    # Verify columns exist
    conn = sqlite3.connect(str(db_file))
    cols = {row[1] for row in conn.execute("PRAGMA table_info('alerts')")}
    conn.close()

    assert "tags" in cols
    assert "note" in cols
    assert "title_key" in cols
    assert "title_params" in cols
    assert "explanation_key" in cols
    assert "explanation_params" in cols
