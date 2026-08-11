from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from my_auth import (
    CredentialMutationDenied,
    CredentialNotFound,
    MemoryChallengeStore,
    MemoryCredentialStore,
    PasskeyConfig,
    PasskeyCredential,
    PasskeyService,
    PasskeyUser,
    SQLiteCredentialStore,
    VerifiedRegistration,
    ensure_sqlite_schema,
)


def _service(store) -> PasskeyService:
    return PasskeyService(
        config=PasskeyConfig(
            rp_id="localhost", rp_name="Test", origin="http://localhost"
        ),
        challenges=MemoryChallengeStore(),
        credentials=store,
    )


def _save(store, user: PasskeyUser, credential_id: bytes) -> None:
    store.save_registration(
        VerifiedRegistration(
            user=user,
            credential=PasskeyCredential(
                credential_id=credential_id,
                user_id=user.user_id,
                public_key=b"key-" + credential_id,
            ),
        )
    )


@pytest.fixture(params=["memory", "sqlite"])
def stores(request: pytest.FixtureRequest, tmp_path: Path):
    if request.param == "memory":
        return MemoryCredentialStore()
    database = tmp_path / "credentials.sqlite3"
    with sqlite3.connect(database) as connection:
        ensure_sqlite_schema(connection)
    return SQLiteCredentialStore(database)


def test_lists_labels_and_removes_only_owned_credentials(stores) -> None:
    own = PasskeyUser("own", b"own-handle", "own")
    other = PasskeyUser("other", b"other-handle", "other")
    _save(stores, own, b"first")
    _save(stores, own, b"second")
    _save(stores, other, b"other")
    service = _service(stores)

    assert {item.credential_id for item in service.list_credentials(user_id="own")} == {
        b"first",
        b"second",
    }
    labeled = service.label_credential(
        user_id="own", credential_id=b"first", label="  Laptop  "
    )
    assert labeled.label == "Laptop"
    with pytest.raises(CredentialNotFound):
        service.label_credential(
            user_id="own", credential_id=b"other", label="Stolen"
        )

    service.remove_credential(user_id="own", credential_id=b"second")
    with pytest.raises(CredentialMutationDenied):
        service.remove_credential(user_id="own", credential_id=b"first")
    assert stores.get_credential(b"first") is not None
    assert stores.get_credential(b"other") is not None


def test_explicit_recovery_policy_can_remove_final_credential(stores) -> None:
    user = PasskeyUser("own", b"own-handle", "own")
    _save(stores, user, b"only")
    service = _service(stores)

    service.remove_credential(
        user_id=user.user_id,
        credential_id=b"only",
        allow_final=True,
    )
    assert service.list_credentials(user_id=user.user_id) == []


def test_label_validation_is_bounded(stores) -> None:
    user = PasskeyUser("own", b"own-handle", "own")
    _save(stores, user, b"only")
    service = _service(stores)
    with pytest.raises(ValueError, match="at most 80"):
        service.label_credential(
            user_id=user.user_id,
            credential_id=b"only",
            label="x" * 81,
        )
