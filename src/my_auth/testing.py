from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime

from .passkeys import (
    ChallengeNotFound,
    ChallengeStore,
    CredentialStore,
    PasskeyCredential,
    PasskeyUser,
    VerifiedRegistration,
)

ChallengeStoreFactory = Callable[[Callable[[], datetime]], ChallengeStore]
CredentialStoreFactory = Callable[[], CredentialStore]


def assert_credential_store_contract(store_factory: CredentialStoreFactory) -> None:
    store = store_factory()
    user = PasskeyUser("user-1", b"stable-handle", "mikolaj", "Mikołaj")
    phone = PasskeyCredential(
        b"phone",
        user.user_id,
        b"phone-public-key",
        sign_count=3,
        transports=["internal"],
        device_type="single_device",
        backed_up=False,
        label="Phone",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    laptop = PasskeyCredential(
        b"laptop",
        user.user_id,
        b"laptop-public-key",
        created_at=datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC),
    )
    store.save_registration(VerifiedRegistration(user, phone))
    store.save_registration(VerifiedRegistration(user, laptop))
    assert store.get_user(user.user_id) == user
    assert store.get_user_by_handle(user.user_handle) == user
    assert store.get_credential(phone.credential_id) == phone
    assert {c.credential_id for c in store.list_credentials_for_user(user.user_id)} == {
        b"phone",
        b"laptop",
    }
    updated = store.compare_and_set_credential_after_login(
        phone.credential_id,
        expected_sign_count=3,
        new_sign_count=4,
        device_type="multi_device",
        backed_up=True,
    )
    assert (
        updated.sign_count == 4
        and updated.device_type == "multi_device"
        and updated.backed_up is True
    )
    assert not store.delete_credential(laptop.credential_id, user_id="other-user")
    assert store.delete_credential(laptop.credential_id, user_id=user.user_id)
    assert store.get_credential(laptop.credential_id) is None


def assert_external_transaction_contract(
    store_factory: Callable[[sqlite3.Connection], CredentialStore],
    schema_initializer: Callable[[sqlite3.Connection], None],
) -> None:
    """Check SQLite shared commit/rollback with a host-owned record.

    The factory receives an active caller-owned SQLite transaction. Non-SQLite
    backends need their own transaction harness; this helper never skips them.
    """

    class SimulatedHostFailure(Exception):
        pass

    connection = sqlite3.connect(":memory:")
    try:
        schema_initializer(connection)
        connection.execute(
            "CREATE TABLE _contract_host_records (user_id TEXT PRIMARY KEY)"
        )
        user = PasskeyUser("u1", b"h1", "Alice")
        reg = VerifiedRegistration(
            user=user,
            credential=PasskeyCredential(
                b"c1", user.user_id, b"pubkey", created_at=datetime.now(UTC)
            ),
        )
        connection.execute("BEGIN IMMEDIATE")
        store = store_factory(connection)
        try:
            connection.execute(
                "INSERT INTO _contract_host_records VALUES (?)", (user.user_id,)
            )
            store.save_registration(reg)
            assert connection.in_transaction, "store committed the caller transaction"
            raise SimulatedHostFailure
        except SimulatedHostFailure:
            connection.rollback()

        connection.execute("BEGIN IMMEDIATE")
        store = store_factory(connection)
        assert store.get_credential(b"c1") is None
        assert store.get_user(user.user_id) is None
        assert store.get_user_by_handle(user.user_handle) is None
        assert (
            connection.execute("SELECT * FROM _contract_host_records").fetchall() == []
        )
        connection.execute(
            "INSERT INTO _contract_host_records VALUES (?)", (user.user_id,)
        )
        store.save_registration(reg)
        assert connection.in_transaction, "store committed the caller transaction"
        connection.commit()

        connection.execute("BEGIN IMMEDIATE")
        store = store_factory(connection)
        assert store.get_credential(b"c1") == reg.credential
        assert store.get_user(user.user_id) == user
        assert connection.execute(
            "SELECT * FROM _contract_host_records"
        ).fetchall() == [(user.user_id,)]
        connection.rollback()
    finally:
        connection.close()


def assert_challenge_store_contract(store_factory: ChallengeStoreFactory) -> None:
    store = store_factory(lambda: datetime.now(UTC))
    _ = store.save(
        key="authentication-flow",
        kind="authentication",
        challenge=b"challenge",
        ttl_seconds=300,
    )
    assert (
        store.pop(key="authentication-flow", kind="authentication").challenge
        == b"challenge"
    )
    _ = store.save(
        key="expired-flow", kind="authentication", challenge=b"expired", ttl_seconds=-1
    )
    try:
        _ = store.pop(key="expired-flow", kind="authentication")
    except ChallengeNotFound:
        pass
    else:
        raise AssertionError("expired challenge must be inaccessible")
