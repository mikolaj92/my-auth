from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from .passkeys import (
    ChallengeNotFound,
    ChallengeStore,
    CredentialStore,
    PasskeyCredential,
    PasskeyUser,
)

ChallengeStoreFactory = Callable[[Callable[[], datetime]], ChallengeStore]
CredentialStoreFactory = Callable[[], CredentialStore]


def assert_credential_store_contract(store_factory: CredentialStoreFactory) -> None:
    store = store_factory()
    user = PasskeyUser(user_id="user-1", user_handle=b"stable-handle", name="mikolaj", display_name="Mikołaj")
    created_at = datetime(2026, 1, 1, tzinfo=UTC)
    phone = PasskeyCredential(
        credential_id=b"phone",
        user_id=user.user_id,
        public_key=b"phone-public-key",
        sign_count=3,
        transports=["internal"],
        device_type="single_device",
        backed_up=False,
        label="Phone",
        created_at=created_at,
    )
    laptop = PasskeyCredential(
        credential_id=b"laptop",
        user_id=user.user_id,
        public_key=b"laptop-public-key",
        created_at=created_at + timedelta(seconds=1),
    )

    store.save_user(user)
    store.save_credential(phone)
    store.save_credential(laptop)

    assert store.get_user(user.user_id) == user
    assert store.get_user_by_handle(user.user_handle) == user
    assert store.get_credential(phone.credential_id) == phone
    assert {credential.credential_id for credential in store.list_credentials_for_user(user.user_id)} == {
        phone.credential_id,
        laptop.credential_id,
    }

    updated = store.update_credential_after_login(
        phone.credential_id,
        sign_count=4,
        device_type="multi_device",
        backed_up=True,
    )

    assert updated.sign_count == 4
    assert updated.device_type == "multi_device"
    assert updated.backed_up is True
    assert store.delete_credential(laptop.credential_id, user_id="other-user") is False
    assert store.get_credential(laptop.credential_id) == laptop
    assert store.delete_credential(laptop.credential_id, user_id=user.user_id) is True
    assert store.get_credential(laptop.credential_id) is None


def assert_challenge_store_contract(store_factory: ChallengeStoreFactory) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = store_factory(lambda: now)
    user = PasskeyUser(user_id="user-1", user_handle=b"stable-handle", name="mikolaj", display_name="Mikołaj")

    store.save(
        key="registration-flow",
        kind="registration",
        challenge=b"registration-challenge",
        ttl_seconds=300,
        user=user,
    )
    consumed = store.pop(key="registration-flow", kind="registration")

    assert consumed.challenge == b"registration-challenge"
    assert consumed.kind == "registration"
    assert consumed.key == "registration-flow"
    assert consumed.user == user
    _assert_missing_challenge(store, key="registration-flow", kind="registration")

    store.save(key="expired-flow", kind="authentication", challenge=b"expired", ttl_seconds=1)
    now += timedelta(seconds=2)

    _assert_missing_challenge(store, key="expired-flow", kind="authentication")


def _assert_missing_challenge(store: ChallengeStore, *, key: str, kind: str) -> None:
    try:
        store.pop(key=key, kind=kind)
    except ChallengeNotFound:
        return
    raise AssertionError("challenge store returned a missing or expired challenge")


__all__ = [
    "ChallengeStoreFactory",
    "CredentialStoreFactory",
    "assert_challenge_store_contract",
    "assert_credential_store_contract",
]
