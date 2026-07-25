from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from my_auth import (
    CredentialCounterConflict,
    MemoryCredentialStore,
    PasskeyConfig,
    PasskeyCredential,
    PasskeyCredentialConflict,
    PasskeyUser,
    SQLiteCredentialStore,
    UnsupportedSQLiteSchema,
    VerifiedRegistration,
    ensure_sqlite_schema,
    inspect_sqlite_schema,
)
import my_auth.sqlite_schema as sqlite_schema


def test_standalone_schema_ddl_failure_rolls_back_everything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = sqlite3.connect(":memory:")
    original_apply = sqlite_schema._apply_schema

    def fail_after_ddl(conn: sqlite3.Connection) -> None:
        original_apply(conn)
        raise RuntimeError("forced schema DDL failure")

    monkeypatch.setattr(sqlite_schema, "_apply_schema", fail_after_ddl)
    with pytest.raises(RuntimeError, match="forced schema DDL failure"):
        ensure_sqlite_schema(connection)
    assert connection.in_transaction is False
    assert inspect_sqlite_schema(connection).state == "empty"
    assert (
        connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        == []
    )
    connection.close()


def test_standalone_schema_interruption_rolls_back_everything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = sqlite3.connect(":memory:")
    original_apply = sqlite_schema._apply_schema

    def interrupt_after_ddl(conn: sqlite3.Connection) -> None:
        original_apply(conn)
        raise KeyboardInterrupt

    monkeypatch.setattr(sqlite_schema, "_apply_schema", interrupt_after_ddl)
    with pytest.raises(KeyboardInterrupt):
        ensure_sqlite_schema(connection)
    assert connection.in_transaction is False
    assert inspect_sqlite_schema(connection).state == "empty"
    connection.close()


def test_standalone_schema_stamp_failure_rolls_back_metadata_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = sqlite3.connect(":memory:")
    original_apply = sqlite_schema._apply_schema

    def fail_stamp(conn: sqlite3.Connection) -> None:
        original_apply(conn)
        conn.execute(
            """
            CREATE TRIGGER fail_schema_stamp
            AFTER INSERT ON my_auth_schema
            BEGIN
                SELECT RAISE(ABORT, 'forced schema stamp failure');
            END
            """
        )

    monkeypatch.setattr(sqlite_schema, "_apply_schema", fail_stamp)
    with pytest.raises(sqlite3.IntegrityError, match="forced schema stamp failure"):
        ensure_sqlite_schema(connection)

    assert connection.in_transaction is False
    assert inspect_sqlite_schema(connection).state == "empty"
    assert (
        connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        == []
    )
    connection.close()


def test_ensure_rejects_unsupported_and_legacy_without_mutation() -> None:
    unsupported = sqlite3.connect(":memory:")
    ensure_sqlite_schema(unsupported)
    unsupported.execute("UPDATE my_auth_schema SET schema_version=99")
    unsupported.commit()
    with pytest.raises(UnsupportedSQLiteSchema):
        ensure_sqlite_schema(unsupported)
    assert unsupported.execute(
        "SELECT schema_version FROM my_auth_schema"
    ).fetchone() == (99,)
    assert unsupported.in_transaction is False
    unsupported.close()

    legacy = sqlite3.connect(":memory:")
    legacy.executescript(
        """
        CREATE TABLE passkey_users (user_id TEXT PRIMARY KEY, user_handle BLOB NOT NULL, name TEXT NOT NULL, display_name TEXT);
        CREATE TABLE passkey_credentials (credential_id BLOB PRIMARY KEY, user_id TEXT NOT NULL, public_key BLOB NOT NULL, sign_count INTEGER NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE passkey_challenges (flow_key TEXT NOT NULL, kind TEXT NOT NULL, challenge BLOB NOT NULL, expires_at TEXT NOT NULL, user_id TEXT, user_handle BLOB, user_name TEXT, user_display_name TEXT, PRIMARY KEY (flow_key, kind));
        """
    )
    tables_before = legacy.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    with pytest.raises(UnsupportedSQLiteSchema):
        ensure_sqlite_schema(legacy)
    assert (
        legacy.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        == tables_before
    )
    assert legacy.in_transaction is False
    legacy.close()


def test_config_requires_valid_positive_and_related_rp_fields() -> None:
    with pytest.raises(ValueError):
        PasskeyConfig(rp_id="", rp_name="Demo", origin="https://example.com")
    with pytest.raises(ValueError):
        PasskeyConfig(
            rp_id="example.com", rp_name="Demo", origin="https://evil.example"
        )
    with pytest.raises(ValueError):
        PasskeyConfig(
            rp_id="example.com",
            rp_name="Demo",
            origin="https://example.com",
            timeout_ms=0,
        )


def test_registration_rejects_credential_user_mismatch_without_persisting(
    tmp_path: Path,
) -> None:
    database = tmp_path / "auth.sqlite"
    with sqlite3.connect(database) as connection:
        ensure_sqlite_schema(connection)

    user = PasskeyUser("user", b"handle", "user")
    credential = PasskeyCredential(b"credential", "other-user", b"key")
    result = VerifiedRegistration(user, credential)
    stores = [
        MemoryCredentialStore(),
        SQLiteCredentialStore(database),
    ]

    for store in stores:
        with pytest.raises(PasskeyCredentialConflict):
            store.save_registration(result)
        assert store.get_user(user.user_id) is None
        assert store.get_credential(credential.credential_id) is None


def test_memory_registration_is_atomic_idempotent_and_conflict_safe() -> None:
    store = MemoryCredentialStore()
    user = PasskeyUser("u", b"handle", "u")
    credential = PasskeyCredential(b"credential", "u", b"key")
    result = VerifiedRegistration(user, credential)
    store.save_registration(result)
    store.save_registration(result)
    with pytest.raises(Exception):
        store.save_registration(
            VerifiedRegistration(
                user, PasskeyCredential(b"credential", "u", b"different")
            )
        )
    assert store.get_user("u") == user


def test_counter_cas_rejects_stale_nonzero_and_preserves_zero_behavior() -> None:
    store = MemoryCredentialStore()
    user = PasskeyUser("u", b"handle", "u")
    store.save_registration(
        VerifiedRegistration(
            user, PasskeyCredential(b"credential", "u", b"key", sign_count=4)
        )
    )
    with pytest.raises(CredentialCounterConflict):
        store.compare_and_set_credential_after_login(
            b"credential",
            expected_sign_count=3,
            new_sign_count=5,
            device_type=None,
            backed_up=None,
        )
    store.save_registration(
        VerifiedRegistration(
            user, PasskeyCredential(b"zero", "u", b"zero-key", sign_count=0)
        )
    )
    updated = store.compare_and_set_credential_after_login(
        b"zero",
        expected_sign_count=0,
        new_sign_count=0,
        device_type=None,
        backed_up=None,
    )
    assert updated.sign_count == 0


def test_schema_must_be_explicit_and_is_versioned(tmp_path: Path) -> None:
    path = tmp_path / "auth.sqlite"
    with sqlite3.connect(path) as connection:
        assert inspect_sqlite_schema(connection).state == "empty"
        ensure_sqlite_schema(connection)
        inspection = inspect_sqlite_schema(connection)
        assert inspection.state == "current"
        assert inspection.version == 2
        assert inspect_sqlite_schema(connection).state == "current"
    with pytest.raises(RuntimeError):
        SQLiteCredentialStore(path.with_name("uninitialized.sqlite"))


def test_store_constructor_rejects_unsupported_schema_version(tmp_path: Path) -> None:
    database = tmp_path / "unsupported-version.sqlite3"
    with sqlite3.connect(database) as connection:
        ensure_sqlite_schema(connection)
        connection.execute("UPDATE my_auth_schema SET schema_version=99")
        connection.commit()
    with pytest.raises(RuntimeError, match="schema is not current"):
        SQLiteCredentialStore(database)


def test_store_constructor_requires_migration_for_legacy_schema() -> None:
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE passkey_users (user_id TEXT PRIMARY KEY, user_handle BLOB NOT NULL, name TEXT NOT NULL, display_name TEXT);
        CREATE TABLE passkey_credentials (credential_id BLOB PRIMARY KEY, user_id TEXT NOT NULL, public_key BLOB NOT NULL, sign_count INTEGER NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE passkey_challenges (flow_key TEXT NOT NULL, kind TEXT NOT NULL, challenge BLOB NOT NULL, expires_at TEXT NOT NULL, user_id TEXT, user_handle BLOB, user_name TEXT, user_display_name TEXT, PRIMARY KEY (flow_key, kind));
        """
    )
    with pytest.raises(RuntimeError, match="requires migration"):
        SQLiteCredentialStore(connection)
    connection.close()


def test_schema_initialization_preserves_unrelated_tables_and_is_idempotent() -> None:
    connection = sqlite3.connect(":memory:")
    connection.commit()
    connection.execute("CREATE TABLE unrelated (value TEXT NOT NULL)")
    connection.execute("INSERT INTO unrelated VALUES ('kept')")
    connection.commit()
    ensure_sqlite_schema(connection)
    ensure_sqlite_schema(connection)
    assert connection.execute("SELECT value FROM unrelated").fetchone() == ("kept",)
    assert inspect_sqlite_schema(connection).state == "current"


def test_inspection_rejects_v2_metadata_with_divergent_layout() -> None:
    connection = sqlite3.connect(":memory:")
    ensure_sqlite_schema(connection)
    connection.execute("DROP INDEX idx_passkey_credentials_user_id")
    connection.commit()

    inspection = inspect_sqlite_schema(connection)

    assert inspection.state == "unsupported"
    assert "idx_passkey_credentials_user_id" in " ".join(inspection.diagnostics)


def test_inspection_rejects_non_cascading_foreign_key() -> None:
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE my_auth_schema (schema_version INTEGER NOT NULL);
        CREATE TABLE passkey_users (user_id TEXT PRIMARY KEY, user_handle TEXT NOT NULL UNIQUE, name TEXT NOT NULL, display_name TEXT);
        CREATE TABLE passkey_credentials (credential_id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES passkey_users(user_id), public_key BLOB NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0, transports TEXT, device_type TEXT, backed_up INTEGER, label TEXT, created_at TEXT NOT NULL);
        CREATE INDEX idx_passkey_credentials_user_id ON passkey_credentials(user_id);
        CREATE TABLE passkey_challenges (key TEXT NOT NULL, kind TEXT NOT NULL, challenge BLOB NOT NULL, expires_at TEXT NOT NULL, user_id TEXT, user_handle TEXT, user_name TEXT, user_display_name TEXT, PRIMARY KEY (key, kind));
        CREATE INDEX idx_passkey_challenges_expires_at ON passkey_challenges(expires_at);
        INSERT INTO my_auth_schema VALUES (2);
        """
    )
    inspection = inspect_sqlite_schema(connection)
    assert inspection.state == "unsupported"
    assert "foreign key" in " ".join(inspection.diagnostics)
    connection.close()


def test_legacy_schema_migration_preserves_optional_fields_and_flow_key() -> None:
    from my_auth import migrate_sqlite_schema

    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE unrelated (value TEXT NOT NULL);
        INSERT INTO unrelated VALUES ('kept');


        CREATE TABLE passkey_users (
            user_id TEXT PRIMARY KEY, user_handle BLOB NOT NULL,
            name TEXT NOT NULL, display_name TEXT
        );
        CREATE TABLE passkey_credentials (
            credential_id BLOB PRIMARY KEY, user_id TEXT NOT NULL,
            public_key BLOB NOT NULL, sign_count INTEGER NOT NULL,
            transports TEXT, device_type TEXT, backed_up INTEGER,
            label TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE passkey_challenges (
            flow_key TEXT NOT NULL, kind TEXT NOT NULL, challenge BLOB NOT NULL,
            expires_at TEXT NOT NULL, user_id TEXT, user_handle BLOB,
            user_name TEXT, user_display_name TEXT,
            PRIMARY KEY (flow_key, kind)
        );
        INSERT INTO passkey_users VALUES ('user-1', X'68616E646C65', 'alice', 'Alice');
        INSERT INTO passkey_credentials VALUES (
            X'0102', 'user-1', X'6B6579', 7, '["internal"]', 'single_device',
            1, 'laptop', '2026-01-01T00:00:00+00:00'
        );
        INSERT INTO passkey_challenges VALUES (
            'flow-1', 'registration', X'6368616C6C656E6765',
            '2026-01-01T00:10:00+00:00', 'user-1', X'68616E646C65', 'alice', 'Alice'
        );
        """
    )

    migrated = migrate_sqlite_schema(connection)

    assert migrated.state == "current"
    assert connection.execute("SELECT value FROM unrelated").fetchone() == ("kept",)
    assert connection.execute(
        "SELECT credential_id,transports,device_type,backed_up,label,created_at "
        "FROM passkey_credentials"
    ).fetchone() == (
        "AQI",
        '["internal"]',
        "single_device",
        1,
        "laptop",
        "2026-01-01T00:00:00+00:00",
    )
    assert connection.execute(
        "SELECT key,kind,user_handle FROM passkey_challenges"
    ).fetchone() == ("flow-1", "registration", "aGFuZGxl")


def test_legacy_schema_migration_rolls_back_source_on_late_failure() -> None:
    from my_auth import migrate_sqlite_schema

    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE unrelated (value TEXT NOT NULL);
        INSERT INTO unrelated VALUES ('kept');
        CREATE TABLE passkey_users (
            user_id TEXT PRIMARY KEY, user_handle BLOB NOT NULL,
            name TEXT NOT NULL, display_name TEXT
        );
        CREATE TABLE passkey_credentials (
            credential_id BLOB PRIMARY KEY, user_id TEXT NOT NULL,
            public_key BLOB NOT NULL, sign_count INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE passkey_challenges (
            flow_key TEXT NOT NULL, kind TEXT NOT NULL, challenge BLOB NOT NULL,
            expires_at TEXT NOT NULL, user_id TEXT, user_handle BLOB,
            user_name TEXT, user_display_name TEXT,
            PRIMARY KEY (flow_key, kind)
        );
        INSERT INTO passkey_users VALUES ('user-1', X'68616E646C65', 'alice', 'Alice');
        INSERT INTO passkey_credentials VALUES (
            X'0102', 'user-1', X'6B6579', 7, '2026-01-01T00:00:00+00:00'
        );
        INSERT INTO passkey_challenges VALUES (
            'flow-1', 'registration', X'6368616C6C656E6765',
            '2026-01-01T00:10:00+00:00', 'user-1', X'68616E646C65', 'alice', 'Alice'
        );
        CREATE INDEX idx_passkey_credentials_user_id ON unrelated(value);
        """
    )
    before_schema = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
    ).fetchall()
    before_rows = {
        table: connection.execute(f"SELECT * FROM {table}").fetchall()
        for table in (
            "unrelated",
            "passkey_users",
            "passkey_credentials",
            "passkey_challenges",
        )
    }

    with pytest.raises(sqlite3.OperationalError, match="already exists"):
        migrate_sqlite_schema(connection)

    assert inspect_sqlite_schema(connection).state == "legacy"
    assert (
        connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
        ).fetchall()
        == before_schema
    )
    for table, rows in before_rows.items():
        assert connection.execute(f"SELECT * FROM {table}").fetchall() == rows
