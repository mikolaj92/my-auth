from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest

from my_auth import (
    MemoryCredentialStore,
    PasskeyCredential,
    PasskeyUser,
    SQLiteCredentialStore,
    VerifiedRegistration,
    ensure_sqlite_schema,
)


def _registration(user: PasskeyUser, credential_id: bytes) -> VerifiedRegistration:
    return VerifiedRegistration(
        user,
        PasskeyCredential(credential_id, user.user_id, b"public-key-" + credential_id),
    )


@pytest.fixture(params=["memory", "sqlite"])
def store(request: pytest.FixtureRequest, tmp_path: Path):
    if request.param == "memory":
        return MemoryCredentialStore()
    database = tmp_path / "guarded-delete.sqlite3"
    with sqlite3.connect(database) as connection:
        ensure_sqlite_schema(connection)
    return SQLiteCredentialStore(database)


def test_default_delete_remains_unrestricted(store) -> None:
    user = PasskeyUser("user", b"handle", "user")
    credential = _registration(user, b"only")
    store.save_registration(credential)

    assert store.delete_credential(credential.credential.credential_id) is True
    assert store.get_credential(credential.credential.credential_id) is None


def test_guarded_delete_refuses_last_credential(store) -> None:
    user = PasskeyUser("user", b"handle", "user")
    credential = _registration(user, b"only")
    store.save_registration(credential)

    assert (
        store.delete_credential(
            credential.credential.credential_id,
            user_id=user.user_id,
            require_remaining=True,
        )
        is False
    )
    assert store.get_credential(credential.credential.credential_id) is not None


def test_external_guarded_delete_serializes_before_count(tmp_path: Path) -> None:
    database = tmp_path / "external-concurrent-guarded-delete.sqlite3"
    with sqlite3.connect(database) as connection:
        ensure_sqlite_schema(connection)
    setup = SQLiteCredentialStore(database)
    user = PasskeyUser("user", b"handle", "user")
    first = _registration(user, b"first")
    second = _registration(user, b"second")
    setup.save_registration(first)
    setup.save_registration(second)

    first_connection = sqlite3.connect(database, timeout=30, check_same_thread=False)
    second_connection = sqlite3.connect(database, timeout=30, check_same_thread=False)
    for connection in (first_connection, second_connection):
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("BEGIN")
    first_store = SQLiteCredentialStore(first_connection, transaction_mode="external")
    second_store = SQLiteCredentialStore(second_connection, transaction_mode="external")
    first_finished = Event()
    second_started = Event()
    release_first = Event()
    first_result: list[bool] = []
    second_result: list[bool] = []
    errors: list[BaseException] = []

    def delete_first() -> None:
        try:
            first_result.append(
                first_store.delete_credential(
                    first.credential.credential_id,
                    user_id=user.user_id,
                    require_remaining=True,
                )
            )
            first_finished.set()
            assert release_first.wait(5)
            first_connection.commit()
        except BaseException as error:
            errors.append(error)

    def delete_second() -> None:
        try:
            assert first_finished.wait(5)
            second_started.set()
            second_result.append(
                second_store.delete_credential(
                    second.credential.credential_id,
                    user_id=user.user_id,
                    require_remaining=True,
                )
            )
            second_connection.commit()
        except sqlite3.OperationalError as error:
            if "locked" not in str(error):
                errors.append(error)
            second_connection.rollback()
            second_result.append(False)
        except BaseException as error:
            errors.append(error)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(delete_first)
        assert first_finished.wait(5)
        second_future = executor.submit(delete_second)
        assert second_started.wait(5)
        release_first.set()
        first_future.result()
        second_future.result()

    first_connection.close()
    second_connection.close()
    assert errors == []
    assert sorted(first_result + second_result) == [False, True]
    assert len(list(setup.list_credentials_for_user(user.user_id))) == 1


def test_external_guarded_delete_rollback_remains_caller_controlled(
    tmp_path: Path,
) -> None:
    database = tmp_path / "external-rollback-guarded-delete.sqlite3"
    with sqlite3.connect(database) as connection:
        ensure_sqlite_schema(connection)
    setup = SQLiteCredentialStore(database)
    user = PasskeyUser("user", b"handle", "user")
    first = _registration(user, b"first")
    second = _registration(user, b"second")
    setup.save_registration(first)
    setup.save_registration(second)

    connection = sqlite3.connect(database)
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("BEGIN")
    store = SQLiteCredentialStore(connection, transaction_mode="external")
    assert store.delete_credential(
        first.credential.credential_id,
        user_id=user.user_id,
        require_remaining=True,
    )
    with sqlite3.connect(database) as observer:
        assert observer.execute(
            "SELECT COUNT(*) FROM passkey_credentials WHERE user_id=?", (user.user_id,)
        ).fetchone() == (2,)
    connection.rollback()
    connection.close()
    assert len(list(setup.list_credentials_for_user(user.user_id))) == 2


def test_concurrent_guarded_deletes_preserve_one_credential(tmp_path: Path) -> None:
    database = tmp_path / "concurrent-guarded-delete.sqlite3"
    with sqlite3.connect(database) as connection:
        ensure_sqlite_schema(connection)
    setup = SQLiteCredentialStore(database)
    user = PasskeyUser("user", b"handle", "user")
    first = _registration(user, b"first")
    second = _registration(user, b"second")
    setup.save_registration(first)
    setup.save_registration(second)

    def delete(credential_id: bytes) -> bool:
        return SQLiteCredentialStore(database).delete_credential(
            credential_id, user_id=user.user_id, require_remaining=True
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                delete,
                (first.credential.credential_id, second.credential.credential_id),
            )
        )

    assert sorted(results) == [False, True]
    assert len(list(setup.list_credentials_for_user(user.user_id))) == 1
