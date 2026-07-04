from __future__ import annotations

import sqlite3

from .passkeys import PASSKEY_SQLITE_CHALLENGE_SCHEMA, PASSKEY_SQLITE_SCHEMA


def sqlite_schema_sql() -> str:
    return f"{PASSKEY_SQLITE_SCHEMA.strip()}\n\n{PASSKEY_SQLITE_CHALLENGE_SCHEMA.strip()}\n"


def ensure_sqlite_schema(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(sqlite_schema_sql())


__all__ = ["ensure_sqlite_schema", "sqlite_schema_sql"]
