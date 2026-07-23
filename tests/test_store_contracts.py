from __future__ import annotations

import sqlite3
from datetime import datetime, UTC
from pathlib import Path

import pytest

from my_auth import (
    PasskeyCredential,
    PasskeyUser,
    SQLiteChallengeStore,
    SQLiteCredentialStore,
    VerifiedRegistration,
    ensure_sqlite_schema,
    inspect_sqlite_schema,
)
from my_auth.testing import (
    assert_challenge_store_contract,
    assert_credential_store_contract,
)


def test_memory_stores_satisfy_passkey_contracts() -> None:
    from my_auth import MemoryChallengeStore, MemoryCredentialStore

    assert_credential_store_contract(MemoryCredentialStore)
    assert_challenge_store_contract(lambda now: MemoryChallengeStore(now=now))


def test_sqlite_stores_satisfy_passkey_contracts(tmp_path: Path) -> None:
    database = tmp_path / "auth.sqlite3"
    with sqlite3.connect(database) as connection:
        ensure_sqlite_schema(connection)
    assert_credential_store_contract(lambda: SQLiteCredentialStore(database))
    assert_challenge_store_contract(lambda now: SQLiteChallengeStore(database, now=now))


def test_canonical_schema_helper_is_explicit_and_versioned(tmp_path: Path) -> None:
    database = tmp_path / "passkeys.sqlite3"
    with sqlite3.connect(database) as connection:
        assert inspect_sqlite_schema(connection).state == "empty"
        ensure_sqlite_schema(connection)
        assert inspect_sqlite_schema(connection).state == "current"
        assert {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        } >= {
            "passkey_users",
            "passkey_credentials",
            "passkey_challenges",
            "my_auth_schema",
        }


def test_operation_mode_external_credential_connection_finishes_each_mutation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "credential-transactions.sqlite3"
    with sqlite3.connect(database) as setup:
        ensure_sqlite_schema(setup)

    connection = sqlite3.connect(database)
    store = SQLiteCredentialStore(connection)
    user = PasskeyUser("user-1", b"handle-1", "mikolaj")
    credential = PasskeyCredential(b"credential-1", user.user_id, b"public-key")
    store.save_registration(VerifiedRegistration(user, credential))
    assert not connection.in_transaction

    with sqlite3.connect(database, timeout=0.1) as observer:
        assert observer.execute(
            "SELECT user_id FROM passkey_users WHERE user_id=?", (user.user_id,)
        ).fetchone() == (user.user_id,)

    with sqlite3.connect(database) as trigger_connection:
        trigger_connection.execute(
            """
            CREATE TRIGGER fail_credential_insert
            AFTER INSERT ON passkey_credentials
            BEGIN
                SELECT RAISE(ABORT, 'forced credential failure');
            END
            """
        )
    failed_user = PasskeyUser("failed-user", b"failed-handle", "failed")
    failed_credential = PasskeyCredential(
        b"failed-credential", failed_user.user_id, b"failed-public-key"
    )
    with pytest.raises(sqlite3.IntegrityError, match="forced credential failure"):
        store.save_registration(VerifiedRegistration(failed_user, failed_credential))
    assert not connection.in_transaction
    assert store.get_user(failed_user.user_id) is None

    with sqlite3.connect(database) as trigger_connection:
        trigger_connection.execute("DROP TRIGGER fail_credential_insert")

    connection.execute("SELECT 1").fetchone()
    connection.close()


def test_operation_mode_external_challenge_connection_finishes_each_mutation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "challenge-transactions.sqlite3"
    with sqlite3.connect(database) as setup:
        ensure_sqlite_schema(setup)

    connection = sqlite3.connect(database)
    store = SQLiteChallengeStore(
        connection,
        now=lambda: datetime(2026, 1, 1, tzinfo=UTC),
    )
    store.save(
        key="flow-1",
        kind="authentication",
        challenge=b"challenge-1",
        ttl_seconds=300,
    )
    assert not connection.in_transaction
    with sqlite3.connect(database, timeout=0.1) as observer:
        assert observer.execute(
            "SELECT challenge FROM passkey_challenges WHERE key=?", ("flow-1",)
        ).fetchone() == (b"challenge-1",)

    with sqlite3.connect(database) as trigger_connection:
        trigger_connection.execute(
            """
            CREATE TRIGGER fail_challenge_insert
            AFTER INSERT ON passkey_challenges
            BEGIN
                SELECT RAISE(ABORT, 'forced challenge failure');
            END
            """
        )
    with pytest.raises(sqlite3.IntegrityError, match="forced challenge failure"):
        store.save(
            key="failed-flow",
            kind="authentication",
            challenge=b"failed-challenge",
            ttl_seconds=300,
        )
    assert not connection.in_transaction
    assert store.cleanup_expired() == 0
    with sqlite3.connect(database, timeout=0.1) as observer:
        assert observer.execute(
            "SELECT 1 FROM passkey_challenges WHERE key=?", ("failed-flow",)
        ).fetchone() is None

    with sqlite3.connect(database) as trigger_connection:
        trigger_connection.execute("DROP TRIGGER fail_challenge_insert")
    connection.close()


def test_external_transaction_mode_leaves_transaction_to_caller(
    tmp_path: Path,
) -> None:
    database = tmp_path / "caller-transaction.sqlite3"
    with sqlite3.connect(database) as setup:
        ensure_sqlite_schema(setup)

    connection = sqlite3.connect(database)
    connection.execute("BEGIN")
    store = SQLiteCredentialStore(connection, transaction_mode="external")
    user = PasskeyUser("caller-user", b"caller-handle", "caller")
    credential = PasskeyCredential(b"caller-credential", user.user_id, b"public-key")
    store.save_registration(VerifiedRegistration(user, credential))
    assert connection.in_transaction
    with sqlite3.connect(database) as observer:
        assert observer.execute(
            "SELECT 1 FROM passkey_users WHERE user_id=?", (user.user_id,)
        ).fetchone() is None

    connection.commit()
    assert not connection.in_transaction
    with sqlite3.connect(database) as observer:
        assert observer.execute(
            "SELECT 1 FROM passkey_users WHERE user_id=?", (user.user_id,)
        ).fetchone() == (1,)
    connection.close()
