"""Tests for SQLite connection helper functions."""

import sqlite3
from pathlib import Path

import pytest

import eve_auth_manager.sqlite.connection_helpers as connection_helpers_module
from eve_auth_manager.sqlite.connection_helpers import (
    create_read_only_connection,
    create_read_write_connection,
    db_connection_manager,
    read_only_uri,
    read_write_uri,
)


def test_sqlite_uri_helpers_build_expected_modes() -> None:
    """SQLite URI builders should append the correct mode query parameter."""
    assert read_only_uri("/tmp/auth.db") == "file:/tmp/auth.db?mode=ro"
    assert read_write_uri("/tmp/auth.db") == "file:/tmp/auth.db?mode=rwc"


def test_create_read_write_connection_creates_schema(tmp_path: Path) -> None:
    """Read-write connections should bootstrap the packaged schema."""
    db_path = tmp_path / "auth.db"

    connection = create_read_write_connection(db_path)
    try:
        table_names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    finally:
        connection.close()

    assert {"credentials", "authorized_characters", "oauth_metadata"} <= table_names


def test_create_read_only_connection_uses_row_factory(tmp_path: Path) -> None:
    """Read-only connections should return sqlite3.Row objects."""
    db_path = tmp_path / "auth.db"
    writable = sqlite3.connect(db_path)
    try:
        writable.execute("CREATE TABLE sample (value INTEGER NOT NULL)")
        writable.execute("INSERT INTO sample (value) VALUES (7)")
        writable.commit()
    finally:
        writable.close()

    connection = create_read_only_connection(db_path)
    try:
        row = connection.execute("SELECT value FROM sample").fetchone()
    finally:
        connection.close()

    assert row is not None
    assert row["value"] == 7


def test_create_read_only_connection_accepts_string_path(tmp_path: Path) -> None:
    """Read-only connections should accept string database paths."""
    db_path = tmp_path / "auth.db"
    writable = sqlite3.connect(db_path)
    try:
        writable.execute("CREATE TABLE sample (value INTEGER NOT NULL)")
        writable.execute("INSERT INTO sample (value) VALUES (11)")
        writable.commit()
    finally:
        writable.close()

    connection = create_read_only_connection(str(db_path))
    try:
        row = connection.execute("SELECT value FROM sample").fetchone()
    finally:
        connection.close()

    assert row is not None
    assert row["value"] == 11


def test_create_read_write_connection_accepts_string_path(tmp_path: Path) -> None:
    """Read-write connections should accept string database paths."""
    db_path = tmp_path / "auth.db"

    connection = create_read_write_connection(str(db_path))
    try:
        row = connection.execute("SELECT 1").fetchone()
    finally:
        connection.close()

    assert row is not None
    assert row[0] == 1


def test_db_connection_manager_closes_read_only_connection(tmp_path: Path) -> None:
    """Connection manager should close read-only connections on exit."""
    db_path = tmp_path / "auth.db"
    writable = sqlite3.connect(db_path)
    try:
        writable.execute("CREATE TABLE sample (value INTEGER NOT NULL)")
        writable.commit()
    finally:
        writable.close()

    with db_connection_manager(db_path, read_only=True) as connection:
        assert connection.execute("SELECT 1").fetchone()[0] == 1

    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")


def test_db_connection_manager_closes_read_write_connection(tmp_path: Path) -> None:
    """Connection manager should close read-write connections on exit."""
    db_path = tmp_path / "auth.db"

    with db_connection_manager(db_path, read_only=False) as connection:
        assert connection.execute("SELECT 1").fetchone()[0] == 1

    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")


def test_db_connection_manager_propagates_read_only_factory_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Connection manager should propagate read-only factory failures."""

    def fake_create_read_only_connection(db_path: str | Path) -> sqlite3.Connection:
        raise RuntimeError("boom")

    monkeypatch.setattr(
        connection_helpers_module,
        "create_read_only_connection",
        fake_create_read_only_connection,
    )

    with pytest.raises(RuntimeError, match="boom"):
        with db_connection_manager(tmp_path / "auth.db", read_only=True):
            raise AssertionError("unreachable")


def test_db_connection_manager_propagates_read_write_factory_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Connection manager should propagate read-write factory failures."""

    def fake_create_read_write_connection(db_path: str | Path) -> sqlite3.Connection:
        raise RuntimeError("boom")

    monkeypatch.setattr(
        connection_helpers_module,
        "create_read_write_connection",
        fake_create_read_write_connection,
    )

    with pytest.raises(RuntimeError, match="boom"):
        with db_connection_manager(tmp_path / "auth.db", read_only=False):
            raise AssertionError("unreachable")


def test_db_connection_manager_raw_generator_handles_uninitialized_connection_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Raw db contextmanager generator should take the no-connection cleanup path."""

    def fake_create_read_only_connection(db_path: str | Path) -> sqlite3.Connection:
        raise RuntimeError("boom")

    monkeypatch.setattr(
        connection_helpers_module,
        "create_read_only_connection",
        fake_create_read_only_connection,
    )

    generator = db_connection_manager.__wrapped__(tmp_path / "auth.db", True)

    with pytest.raises(RuntimeError, match="boom"):
        next(generator)


def test_db_connection_manager_handles_none_connection_without_close(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Connection manager should tolerate a factory returning None."""

    def fake_create_read_only_connection(db_path: str | Path) -> sqlite3.Connection:
        return None

    monkeypatch.setattr(
        connection_helpers_module,
        "create_read_only_connection",
        fake_create_read_only_connection,
    )

    with db_connection_manager(tmp_path / "auth.db", read_only=True) as connection:
        assert connection is None
