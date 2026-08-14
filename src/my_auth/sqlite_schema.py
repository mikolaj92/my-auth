from __future__ import annotations

import sqlite3
from base64 import urlsafe_b64encode
from dataclasses import dataclass
from typing import Literal, cast

from .passkeys import PASSKEY_SQLITE_CHALLENGE_SCHEMA, PASSKEY_SQLITE_SCHEMA

CURRENT_SCHEMA_VERSION = 3

PASSKEY_ENROLLMENT_CAPABILITY_SCHEMA = """
CREATE TABLE IF NOT EXISTS passkey_enrollment_capabilities (
 capability_id TEXT PRIMARY KEY,
 token_hash TEXT NOT NULL UNIQUE,
 purpose TEXT NOT NULL CHECK (purpose IN ('invitation', 'account_recovery')),
 subject TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 issued_by TEXT,
 claimed_flow_id TEXT UNIQUE,
 claimed_at TEXT,
 consumed_at TEXT,
 revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_passkey_enrollment_capabilities_expires_at
ON passkey_enrollment_capabilities(expires_at);
"""


class SQLiteSchemaError(RuntimeError):
    """Base class for explicit schema lifecycle failures."""


class UnsupportedSQLiteSchema(SQLiteSchemaError):
    pass


@dataclass(frozen=True)
class SQLiteSchemaInspection:
    """Schema inspection result.

    Runtime stores accept only ``current``. ``legacy`` is not a live
    read/write layout: it gates the explicit one-shot
    ``migrate_sqlite_schema`` upgrade. ``empty`` and
    ``canonical_unversioned`` are initialized with ``ensure_sqlite_schema``.
    Unsupported layouts fail closed.
    """

    state: Literal["empty", "canonical_unversioned", "legacy", "current", "unsupported"]
    version: int | None = None
    diagnostics: tuple[str, ...] = ()


def _fetchall(cursor: sqlite3.Cursor) -> list[tuple[object, ...]]:
    return cast(list[tuple[object, ...]], cursor.fetchall())


def _as_int(value: object) -> int:
    return int(cast(str | bytes | int | float, value))


def _fetchone(cursor: sqlite3.Cursor) -> tuple[object, ...] | None:
    return cast(tuple[object, ...] | None, cursor.fetchone())


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in _fetchall(
            connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        )
    }


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {
        str(row[1])
        for row in _fetchall(connection.execute(f"PRAGMA table_info({table})"))
    }


_CANONICAL_COLUMNS: dict[str, tuple[tuple[str, str, int, int, object], ...]] = {
    "my_auth_schema": (("schema_version", "INTEGER", 1, 0, None),),
    "passkey_users": (
        ("user_id", "TEXT", 0, 1, None),
        ("user_handle", "TEXT", 1, 0, None),
        ("name", "TEXT", 1, 0, None),
        ("display_name", "TEXT", 0, 0, None),
    ),
    "passkey_credentials": (
        ("credential_id", "TEXT", 0, 1, None),
        ("user_id", "TEXT", 1, 0, None),
        ("public_key", "BLOB", 1, 0, None),
        ("sign_count", "INTEGER", 1, 0, "0"),
        ("transports", "TEXT", 0, 0, None),
        ("device_type", "TEXT", 0, 0, None),
        ("backed_up", "INTEGER", 0, 0, None),
        ("label", "TEXT", 0, 0, None),
        ("created_at", "TEXT", 1, 0, None),
    ),
    "passkey_challenges": (
        ("key", "TEXT", 1, 1, None),
        ("kind", "TEXT", 1, 2, None),
        ("challenge", "BLOB", 1, 0, None),
        ("expires_at", "TEXT", 1, 0, None),
        ("user_id", "TEXT", 0, 0, None),
        ("user_handle", "TEXT", 0, 0, None),
        ("user_name", "TEXT", 0, 0, None),
        ("user_display_name", "TEXT", 0, 0, None),
        ("registration_kind", "TEXT", 0, 0, None),
        ("capability_id", "TEXT", 0, 0, None),
    ),
    "passkey_enrollment_capabilities": (
        ("capability_id", "TEXT", 0, 1, None),
        ("token_hash", "TEXT", 1, 0, None),
        ("purpose", "TEXT", 1, 0, None),
        ("subject", "TEXT", 1, 0, None),
        ("expires_at", "TEXT", 1, 0, None),
        ("issued_by", "TEXT", 0, 0, None),
        ("claimed_flow_id", "TEXT", 0, 0, None),
        ("claimed_at", "TEXT", 0, 0, None),
        ("consumed_at", "TEXT", 0, 0, None),
        ("revoked_at", "TEXT", 0, 0, None),
    ),
}


def _has_unique_column_index(
    connection: sqlite3.Connection, table: str, column: str
) -> bool:
    return any(
        _as_int(row[2]) == 1
        and [
            item[2]
            for item in _fetchall(connection.execute(f"PRAGMA index_info({row[1]})"))
        ]
        == [column]
        for row in _fetchall(connection.execute(f"PRAGMA index_list({table})"))
    )


def _canonical_layout_diagnostics(
    connection: sqlite3.Connection, *, require_metadata: bool = True
) -> tuple[str, ...]:
    diagnostics: list[str] = []
    tables = _tables(connection)
    for table, expected in _CANONICAL_COLUMNS.items():
        if table == "my_auth_schema" and not require_metadata:
            continue
        if table == "passkey_enrollment_capabilities" and table not in tables:
            continue
        actual = tuple(
            (str(row[1]), str(row[2]).upper(), _as_int(row[3]), _as_int(row[5]), row[4])
            for row in _fetchall(connection.execute(f"PRAGMA table_info({table})"))
        )
        if actual != expected:
            diagnostics.append(f"divergent columns ({table})")

    indexes = {
        (str(row[1]), _as_int(row[2]))
        for row in _fetchall(
            connection.execute("PRAGMA index_list(passkey_credentials)")
        )
    }
    if ("idx_passkey_credentials_user_id", 0) not in indexes:
        diagnostics.append("missing index (idx_passkey_credentials_user_id)")
    indexes = {
        (str(row[1]), _as_int(row[2]))
        for row in _fetchall(
            connection.execute("PRAGMA index_list(passkey_challenges)")
        )
    }
    if ("idx_passkey_challenges_expires_at", 0) not in indexes:
        diagnostics.append("missing index (idx_passkey_challenges_expires_at)")
    if not _has_unique_column_index(connection, "passkey_users", "user_handle"):
        diagnostics.append("missing unique index (passkey_users.user_handle)")
    if "passkey_enrollment_capabilities" in tables:
        enrollment_indexes = {
            (str(row[1]), _as_int(row[2]))
            for row in _fetchall(
                connection.execute("PRAGMA index_list(passkey_enrollment_capabilities)")
            )
        }
        if (
            "idx_passkey_enrollment_capabilities_expires_at",
            0,
        ) not in enrollment_indexes:
            diagnostics.append(
                "missing index (idx_passkey_enrollment_capabilities_expires_at)"
            )
        if not _has_unique_column_index(
            connection, "passkey_enrollment_capabilities", "token_hash"
        ):
            diagnostics.append(
                "missing unique index (passkey_enrollment_capabilities.token_hash)"
            )
        if not _has_unique_column_index(
            connection, "passkey_enrollment_capabilities", "claimed_flow_id"
        ):
            diagnostics.append(
                "missing unique index (passkey_enrollment_capabilities.claimed_flow_id)"
            )

    foreign_keys = [
        tuple(row[2:7])
        for row in _fetchall(
            connection.execute("PRAGMA foreign_key_list(passkey_credentials)")
        )
    ]
    if foreign_keys != [
        ("passkey_users", "user_id", "user_id", "NO ACTION", "CASCADE")
    ]:
        diagnostics.append("divergent foreign key (passkey_credentials.user_id)")
    return tuple(diagnostics)


def _v2_layout_diagnostics(connection: sqlite3.Connection) -> tuple[str, ...]:
    diagnostics: list[str] = []
    indexes = {
        (str(row[1]), _as_int(row[2]))
        for row in _fetchall(
            connection.execute("PRAGMA index_list(passkey_credentials)")
        )
    }
    if ("idx_passkey_credentials_user_id", 0) not in indexes:
        diagnostics.append("missing index (idx_passkey_credentials_user_id)")
    challenge_indexes = {
        (str(row[1]), _as_int(row[2]))
        for row in _fetchall(
            connection.execute("PRAGMA index_list(passkey_challenges)")
        )
    }
    if ("idx_passkey_challenges_expires_at", 0) not in challenge_indexes:
        diagnostics.append("missing index (idx_passkey_challenges_expires_at)")
    foreign_keys = [
        tuple(row[2:7])
        for row in _fetchall(
            connection.execute("PRAGMA foreign_key_list(passkey_credentials)")
        )
    ]
    if foreign_keys != [
        ("passkey_users", "user_id", "user_id", "NO ACTION", "CASCADE")
    ]:
        diagnostics.append("divergent foreign key (passkey_credentials.user_id)")
    return tuple(diagnostics)


def sqlite_schema_sql() -> str:
    return (
        "CREATE TABLE IF NOT EXISTS my_auth_schema (schema_version INTEGER NOT NULL);\n"
        f"{PASSKEY_SQLITE_SCHEMA.strip()}\n\n{PASSKEY_SQLITE_CHALLENGE_SCHEMA.strip()}\n\n"
        f"{PASSKEY_ENROLLMENT_CAPABILITY_SCHEMA.strip()}\n"
    )


def _apply_statements(connection: sqlite3.Connection, sql: str) -> None:
    for statement in (item.strip() for item in sql.split(";") if item.strip()):
        _ = connection.execute(statement)


def _apply_schema(connection: sqlite3.Connection) -> None:
    _apply_statements(connection, sqlite_schema_sql())


def _apply_enrollment_schema(connection: sqlite3.Connection) -> None:
    _apply_statements(connection, PASSKEY_ENROLLMENT_CAPABILITY_SCHEMA)


def _validate_transaction_mode(transaction_mode: str) -> None:
    if transaction_mode not in {"standalone", "external"}:
        raise ValueError("transaction_mode must be 'standalone' or 'external'")


def _foreign_keys_enabled(connection: sqlite3.Connection) -> bool:
    row = _fetchone(connection.execute("PRAGMA foreign_keys"))
    return row is not None and _as_int(row[0]) == 1


def inspect_sqlite_schema(connection: sqlite3.Connection) -> SQLiteSchemaInspection:
    tables = _tables(connection)
    required = {"passkey_users", "passkey_credentials", "passkey_challenges"}
    if not tables or tables == {"sqlite_sequence"}:
        return SQLiteSchemaInspection("empty")
    if not tables.intersection(required | {"my_auth_schema"}):
        return SQLiteSchemaInspection("empty")
    if not required.issubset(tables):
        return SQLiteSchemaInspection(
            "unsupported",
            diagnostics=(f"missing tables: {', '.join(sorted(required - tables))}",),
        )

    columns = {table: _columns(connection, table) for table in required}
    challenge_columns = columns["passkey_challenges"]
    has_flow_key = "flow_key" in challenge_columns
    has_key = "key" in challenge_columns
    if has_flow_key and has_key:
        return SQLiteSchemaInspection(
            "unsupported",
            diagnostics=("challenge table has both flow_key and key columns",),
        )
    # Pre-versioned 0.1 layout (flow_key). Migrate-only — never a live dual path.
    if has_flow_key and not has_key:
        expected_legacy = {
            "passkey_users": {"user_id", "user_handle", "name", "display_name"},
            "passkey_credentials": {
                "credential_id",
                "user_id",
                "public_key",
                "sign_count",
                "created_at",
            },
            "passkey_challenges": {
                "flow_key",
                "kind",
                "challenge",
                "expires_at",
                "user_id",
                "user_handle",
                "user_name",
                "user_display_name",
            },
        }
        missing = [
            f"{table}: {', '.join(sorted(expected_legacy[table] - columns[table]))}"
            for table in required
            if expected_legacy[table] - columns[table]
        ]
        if missing:
            return SQLiteSchemaInspection(
                "unsupported",
                diagnostics=tuple(f"missing columns ({item})" for item in missing),
            )
        if "my_auth_schema" in tables:
            return SQLiteSchemaInspection(
                "unsupported", diagnostics=("legacy layout has schema metadata",)
            )
        return SQLiteSchemaInspection(
            "legacy", diagnostics=("legacy flow_key challenge layout",)
        )

    if "my_auth_schema" not in tables:
        diagnostics = _canonical_layout_diagnostics(connection, require_metadata=False)
        if diagnostics:
            return SQLiteSchemaInspection("unsupported", diagnostics=diagnostics)
        return SQLiteSchemaInspection("canonical_unversioned")

    version_rows = _fetchall(
        connection.execute("SELECT schema_version FROM my_auth_schema")
    )
    if len(version_rows) != 1:
        return SQLiteSchemaInspection(
            "unsupported", diagnostics=("schema metadata must contain one row",)
        )
    try:
        version = _as_int(version_rows[0][0])
    except (TypeError, ValueError):
        return SQLiteSchemaInspection(
            "unsupported", diagnostics=("schema version must be an integer",)
        )
    if version == CURRENT_SCHEMA_VERSION:
        diagnostics = _canonical_layout_diagnostics(connection)
        if diagnostics:
            return SQLiteSchemaInspection("unsupported", diagnostics=diagnostics)
        return SQLiteSchemaInspection("current", version=version)
    if version == 2:
        expected_v2 = {
            name: columns
            for name, columns in _CANONICAL_COLUMNS.items()
            if name != "passkey_challenges"
        }
        expected_v2["passkey_challenges"] = _CANONICAL_COLUMNS[
            "passkey_challenges"
        ][:-2]
        actual_v2 = tuple(
            (
                str(row[1]),
                str(row[2]).upper(),
                _as_int(row[3]),
                _as_int(row[5]),
                row[4],
            )
            for row in _fetchall(
                connection.execute("PRAGMA table_info(passkey_challenges)")
            )
        )
        if actual_v2 == expected_v2["passkey_challenges"]:
            diagnostics = _v2_layout_diagnostics(connection)
            if diagnostics:
                return SQLiteSchemaInspection("unsupported", diagnostics=diagnostics)
            return SQLiteSchemaInspection(
                "legacy", version=2, diagnostics=("schema v2",)
            )
    return SQLiteSchemaInspection(
        "unsupported",
        version=version,
        diagnostics=(f"schema version {version} is not supported",),
    )


def ensure_sqlite_schema(
    connection: sqlite3.Connection,
    *,
    transaction_mode: Literal["standalone", "external"] = "standalone",
) -> None:
    """Create/stamp canonical schema; standalone mode owns its commit."""
    _validate_transaction_mode(transaction_mode)
    if transaction_mode == "external":
        if not connection.in_transaction:
            raise SQLiteSchemaError(
                "external schema mode requires an active transaction"
            )
        if not _foreign_keys_enabled(connection):
            raise SQLiteSchemaError(
                "external schema mode requires PRAGMA foreign_keys=ON before the transaction"
            )
    elif connection.in_transaction:
        raise SQLiteSchemaError(
            "schema initialization requires a connection with no pending transaction"
        )
    else:
        _ = connection.execute("PRAGMA foreign_keys = ON")
    state = inspect_sqlite_schema(connection)
    if state.state == "current":
        if transaction_mode == "standalone":
            _ = connection.execute("BEGIN IMMEDIATE")
            try:
                _apply_enrollment_schema(connection)
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        else:
            _apply_enrollment_schema(connection)
        return
    if state.state not in {"empty", "canonical_unversioned"}:
        raise UnsupportedSQLiteSchema(
            f"cannot ensure {state.state}: {'; '.join(state.diagnostics)}"
        )
    if transaction_mode == "external":
        if state.state == "empty":
            _apply_schema(connection)
        else:
            _ = connection.execute(
                "CREATE TABLE IF NOT EXISTS my_auth_schema (schema_version INTEGER NOT NULL)"
            )
            _apply_enrollment_schema(connection)
        _ = connection.execute("DELETE FROM my_auth_schema")
        _ = connection.execute(
            "INSERT INTO my_auth_schema(schema_version) VALUES (?)",
            (CURRENT_SCHEMA_VERSION,),
        )
        return
    try:
        _ = connection.execute("BEGIN IMMEDIATE")
        state = inspect_sqlite_schema(connection)
        if state.state == "current":
            _apply_enrollment_schema(connection)
            connection.commit()
            return
        if state.state not in {"empty", "canonical_unversioned"}:
            raise UnsupportedSQLiteSchema(
                f"cannot ensure {state.state}: {'; '.join(state.diagnostics)}"
            )
        if state.state == "empty":
            _apply_schema(connection)
        else:
            _ = connection.execute(
                "CREATE TABLE IF NOT EXISTS my_auth_schema (schema_version INTEGER NOT NULL)"
            )
            _apply_enrollment_schema(connection)
        _ = connection.execute("DELETE FROM my_auth_schema")
        _ = connection.execute(
            "INSERT INTO my_auth_schema(schema_version) VALUES (?)",
            (CURRENT_SCHEMA_VERSION,),
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise


def _b64(value: object) -> object:
    if isinstance(value, bytes):
        return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
    return value


def migrate_sqlite_schema(
    connection: sqlite3.Connection,
    *,
    transaction_mode: Literal["standalone", "external"] = "standalone",
) -> SQLiteSchemaInspection:
    """One-shot upgrade from supported legacy layouts to ``current``.

    This is the only upgrade path for ``legacy`` inspections (0.1 ``flow_key``
    layout or schema v2). It is not a runtime dual-read: stores reject
    non-``current`` schemas until migration succeeds. Ambiguous layouts fail
    closed; source tables are preserved when standalone migration rolls back.
    """
    _validate_transaction_mode(transaction_mode)
    if transaction_mode == "external":
        if not connection.in_transaction:
            raise SQLiteSchemaError(
                "external schema mode requires an active transaction"
            )
        if not _foreign_keys_enabled(connection):
            raise SQLiteSchemaError(
                "external schema mode requires PRAGMA foreign_keys=ON before the transaction"
            )
    elif connection.in_transaction:
        raise SQLiteSchemaError(
            "schema migration requires a connection with no pending transaction"
        )
    else:
        _ = connection.execute("PRAGMA foreign_keys = ON")
    state = inspect_sqlite_schema(connection)
    if state.state == "current":
        return state
    if state.state in {"empty", "canonical_unversioned"}:
        ensure_sqlite_schema(connection, transaction_mode=transaction_mode)
        return inspect_sqlite_schema(connection)
    if state.state != "legacy":
        raise UnsupportedSQLiteSchema(
            f"cannot migrate schema: {'; '.join(state.diagnostics)}"
        )
    if state.version == 2:
        try:
            if transaction_mode == "standalone":
                _ = connection.execute("BEGIN IMMEDIATE")
            _ = connection.execute(
                "ALTER TABLE passkey_challenges ADD COLUMN registration_kind TEXT"
            )
            _ = connection.execute(
                "ALTER TABLE passkey_challenges ADD COLUMN capability_id TEXT"
            )
            _apply_enrollment_schema(connection)
            _ = connection.execute("UPDATE my_auth_schema SET schema_version=3")
            if transaction_mode == "standalone":
                connection.commit()
        except Exception:
            if transaction_mode == "standalone":
                connection.rollback()
            raise
        return inspect_sqlite_schema(connection)
    try:
        if transaction_mode == "standalone":
            _ = connection.execute("BEGIN IMMEDIATE")
        _ = connection.execute(
            "CREATE TABLE passkey_users_v2 (user_id TEXT PRIMARY KEY, user_handle TEXT NOT NULL UNIQUE, name TEXT NOT NULL, display_name TEXT)"
        )
        _ = connection.execute(
            "CREATE TABLE passkey_credentials_v2 (credential_id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES passkey_users_v2(user_id) ON DELETE CASCADE, public_key BLOB NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0, transports TEXT, device_type TEXT, backed_up INTEGER, label TEXT, created_at TEXT NOT NULL)"
        )
        _ = connection.execute(
            "CREATE TABLE passkey_challenges_v2 (key TEXT NOT NULL, kind TEXT NOT NULL, challenge BLOB NOT NULL, expires_at TEXT NOT NULL, user_id TEXT, user_handle TEXT, user_name TEXT, user_display_name TEXT, registration_kind TEXT, capability_id TEXT, PRIMARY KEY (key, kind))"
        )
        for row in _fetchall(
            connection.execute(
                "SELECT user_id,user_handle,name,display_name FROM passkey_users"
            )
        ):
            _ = connection.execute(
                "INSERT INTO passkey_users_v2 VALUES(?,?,?,?)",
                (row[0], _b64(row[1]), row[2], row[3]),
            )
        credential_columns = _columns(connection, "passkey_credentials")
        required = {
            "credential_id",
            "user_id",
            "public_key",
            "sign_count",
            "created_at",
        }
        if not required.issubset(credential_columns):
            raise UnsupportedSQLiteSchema("legacy credentials missing required columns")
        optional = [
            name
            for name in ("transports", "device_type", "backed_up", "label")
            if name in credential_columns
        ]
        select = "credential_id,user_id,public_key,sign_count"
        if optional:
            select += "," + ",".join(optional)
        select += ",created_at"
        for row in _fetchall(
            connection.execute(f"SELECT {select} FROM passkey_credentials")
        ):
            values = list(row)
            credential_id = _b64(values.pop(0))
            user_id, public_key, sign_count = values[:3]
            fields = {name: values[3 + i] for i, name in enumerate(optional)}
            created_at = values[-1]
            _ = connection.execute(
                "INSERT INTO passkey_credentials_v2 VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    credential_id,
                    user_id,
                    public_key,
                    sign_count,
                    fields.get("transports"),
                    fields.get("device_type"),
                    fields.get("backed_up"),
                    fields.get("label"),
                    created_at,
                ),
            )
        challenge_columns = _columns(connection, "passkey_challenges")
        if "flow_key" not in challenge_columns or "key" in challenge_columns:
            raise UnsupportedSQLiteSchema(
                "cannot migrate schema: expected exclusive legacy flow_key column"
            )
        for row in _fetchall(
            connection.execute(
                "SELECT flow_key,kind,challenge,expires_at,user_id,user_handle,user_name,user_display_name FROM passkey_challenges"
            )
        ):
            values = list(row)
            values[5] = _b64(values[5])
            _ = connection.execute(
                "INSERT INTO passkey_challenges_v2 VALUES(?,?,?,?,?,?,?,?,?,?)",
                [*values, None, None],
            )
        source_counts: dict[str, int] = {}
        for table in ("passkey_users", "passkey_credentials", "passkey_challenges"):
            count_row = _fetchone(connection.execute(f"SELECT COUNT(*) FROM {table}"))
            if count_row is None:
                raise SQLiteSchemaError("missing source row count")
            source_counts[table] = _as_int(count_row[0])
        target_counts: dict[str, int] = {}
        for source in source_counts:
            count_row = _fetchone(
                connection.execute(f"SELECT COUNT(*) FROM {source}_v2")
            )
            if count_row is None:
                raise SQLiteSchemaError("missing target row count")
            target_counts[source] = _as_int(count_row[0])
        mismatched = [
            f"{table}: source={source_counts[table]} target={target_counts[table]}"
            for table in source_counts
            if source_counts[table] != target_counts[table]
        ]
        if mismatched:
            raise SQLiteSchemaError(
                "migration row count validation failed: " + "; ".join(mismatched)
            )
        for table in ("passkey_credentials", "passkey_challenges", "passkey_users"):
            _ = connection.execute(f"DROP TABLE {table}")
        _ = connection.execute("ALTER TABLE passkey_users_v2 RENAME TO passkey_users")
        _ = connection.execute(
            "ALTER TABLE passkey_credentials_v2 RENAME TO passkey_credentials"
        )
        _ = connection.execute(
            "ALTER TABLE passkey_challenges_v2 RENAME TO passkey_challenges"
        )
        _ = connection.execute(
            "CREATE INDEX idx_passkey_credentials_user_id ON passkey_credentials(user_id)"
        )
        _ = connection.execute(
            "CREATE INDEX idx_passkey_challenges_expires_at ON passkey_challenges(expires_at)"
        )
        _ = connection.execute(
            "CREATE TABLE my_auth_schema (schema_version INTEGER NOT NULL)"
        )
        _ = connection.execute("INSERT INTO my_auth_schema VALUES (3)")
        _apply_enrollment_schema(connection)
        if _fetchone(connection.execute("PRAGMA foreign_key_check")) is not None:
            raise SQLiteSchemaError("foreign key check failed during migration")
        if transaction_mode == "standalone":
            connection.commit()
    except Exception:
        if transaction_mode == "standalone":
            connection.rollback()
        raise
    return inspect_sqlite_schema(connection)


__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "PASSKEY_ENROLLMENT_CAPABILITY_SCHEMA",
    "SQLiteSchemaError",
    "UnsupportedSQLiteSchema",
    "SQLiteSchemaInspection",
    "ensure_sqlite_schema",
    "inspect_sqlite_schema",
    "migrate_sqlite_schema",
    "sqlite_schema_sql",
]
