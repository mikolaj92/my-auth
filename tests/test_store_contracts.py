from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from my_auth import (
    MemoryChallengeStore,
    MemoryCredentialStore,
    SQLiteChallengeStore,
    SQLiteCredentialStore,
)
from my_auth.sqlite_schema import ensure_sqlite_schema, sqlite_schema_sql
from my_auth.testing import assert_challenge_store_contract, assert_credential_store_contract


def test_memory_stores_satisfy_passkey_contracts() -> None:
    # Given: process-local stores used by app tests and examples.
    credential_factory = MemoryCredentialStore
    challenge_factory = _memory_challenge_factory

    # When: the shared contracts exercise the stores.
    assert_credential_store_contract(credential_factory)
    assert_challenge_store_contract(challenge_factory)

    # Then: no assertion is raised by the reusable contract helpers.


def test_sqlite_stores_satisfy_passkey_contracts(tmp_path: Path) -> None:
    # Given: durable SQLite stores using independent database files.
    credential_database = tmp_path / "credentials.sqlite3"
    challenge_database = tmp_path / "challenges.sqlite3"

    # When: the shared contracts exercise fresh store instances.
    assert_credential_store_contract(lambda: SQLiteCredentialStore(credential_database))
    assert_challenge_store_contract(
        lambda now: SQLiteChallengeStore(challenge_database, now=now),
    )

    # Then: no assertion is raised by the reusable contract helpers.


def test_canonical_sqlite_schema_helper_creates_passkey_tables(tmp_path: Path) -> None:
    # Given: an app-owned SQLite connection with no passkey tables.
    database = tmp_path / "passkeys.sqlite3"

    # When: the canonical helper initializes the shared my-auth schema.
    with sqlite3.connect(database) as connection:
        ensure_sqlite_schema(connection)
        tables = _sqlite_names(connection, "table")
        indexes = _sqlite_names(connection, "index")
        foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(passkey_credentials)",
        ).fetchall()

    # Then: current and future apps can inspect one canonical schema contract.
    assert "passkey_users" in tables
    assert "passkey_credentials" in tables
    assert "passkey_challenges" in tables
    assert "idx_passkey_credentials_user_id" in indexes
    assert "idx_passkey_challenges_expires_at" in indexes
    assert any(row[2] == "passkey_users" for row in foreign_keys)
    assert "passkey_users" in sqlite_schema_sql()


def _memory_challenge_factory(now: Callable[[], datetime]) -> MemoryChallengeStore:
    return MemoryChallengeStore(now=now)


def _sqlite_names(connection: sqlite3.Connection, kind: str) -> set[str]:
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = ?",
        (kind,),
    ).fetchall()
    return {str(row[0]) for row in rows}
