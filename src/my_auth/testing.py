from __future__ import annotations
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
        return
    raise AssertionError("store returned expired challenge")


__all__ = ["assert_challenge_store_contract", "assert_credential_store_contract"]
