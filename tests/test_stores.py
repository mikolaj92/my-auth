from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine

from my_auth import (
    MemoryChallengeStore,
    PasskeyConfig,
    PasskeyCredential,
    PasskeyService,
    PasskeyUser,
    SQLiteCredentialStore,
)
from my_auth.passkeys import CredentialNotFound
from my_auth.sqlalchemy_store import SQLAlchemyCredentialStore


@pytest.fixture(params=["sqlite", "sqlalchemy"])
def store(request: pytest.FixtureRequest):
    if request.param == "sqlite":
        connection = sqlite3.connect(":memory:")
        sqlite_store = SQLiteCredentialStore(connection)
        sqlite_store.create_tables()
        yield sqlite_store
        connection.close()
    else:
        engine = create_engine("sqlite://")
        sqlalchemy_store = SQLAlchemyCredentialStore(engine)
        sqlalchemy_store.create_tables()
        yield sqlalchemy_store
        engine.dispose()


def make_user(**overrides) -> PasskeyUser:
    defaults = dict(user_id="u1", user_handle=b"handle-1", name="mikolaj", display_name="Mikolaj")
    defaults.update(overrides)
    return PasskeyUser(**defaults)


def make_credential(**overrides) -> PasskeyCredential:
    defaults = dict(
        credential_id=b"credential-1",
        user_id="u1",
        public_key=b"public-key",
        sign_count=3,
        transports=["internal", "hybrid"],
        device_type="multi_device",
        backed_up=True,
        label="phone",
        created_at=datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
    )
    defaults.update(overrides)
    return PasskeyCredential(**defaults)


def test_save_and_get_user_roundtrip(store) -> None:
    user = make_user()
    store.save_user(user)

    assert store.get_user("u1") == user
    assert store.get_user_by_handle(b"handle-1") == user
    assert store.get_user("missing") is None
    assert store.get_user_by_handle(b"missing") is None


def test_save_user_is_idempotent_and_updates_fields(store) -> None:
    store.save_user(make_user())
    store.save_user(make_user(name="renamed", display_name=None))

    updated = store.get_user("u1")
    assert updated is not None
    assert updated.name == "renamed"
    assert updated.display_name is None


def test_save_and_get_credential_roundtrip(store) -> None:
    store.save_user(make_user())
    credential = make_credential()
    store.save_credential(credential)

    loaded = store.get_credential(b"credential-1")
    assert loaded == credential
    assert store.get_credential(b"missing") is None


def test_credential_with_defaults_roundtrip(store) -> None:
    store.save_user(make_user())
    credential = make_credential(transports=[], device_type=None, backed_up=None, label=None)
    store.save_credential(credential)

    loaded = store.get_credential(b"credential-1")
    assert loaded is not None
    assert loaded.transports == []
    assert loaded.device_type is None
    assert loaded.backed_up is None
    assert loaded.label is None


def test_save_credential_upserts(store) -> None:
    store.save_user(make_user())
    store.save_credential(make_credential())
    store.save_credential(make_credential(sign_count=9, label="renamed phone"))

    loaded = store.get_credential(b"credential-1")
    assert loaded is not None
    assert loaded.sign_count == 9
    assert loaded.label == "renamed phone"


def test_list_credentials_for_user(store) -> None:
    store.save_user(make_user())
    store.save_user(make_user(user_id="u2", user_handle=b"handle-2"))
    store.save_credential(make_credential(credential_id=b"phone"))
    store.save_credential(make_credential(credential_id=b"laptop"))
    store.save_credential(make_credential(credential_id=b"other", user_id="u2"))

    ids = {credential.credential_id for credential in store.list_credentials_for_user("u1")}
    assert ids == {b"phone", b"laptop"}
    assert store.list_credentials_for_user("nobody") == []


def test_update_credential_after_login(store) -> None:
    store.save_user(make_user())
    store.save_credential(make_credential(sign_count=3, device_type=None, backed_up=None))

    updated = store.update_credential_after_login(
        b"credential-1", sign_count=4, device_type="multi_device", backed_up=True
    )

    assert updated.sign_count == 4
    assert updated.device_type == "multi_device"
    assert updated.backed_up is True
    reloaded = store.get_credential(b"credential-1")
    assert reloaded is not None
    assert reloaded.sign_count == 4


def test_update_unknown_credential_raises(store) -> None:
    with pytest.raises(CredentialNotFound):
        store.update_credential_after_login(
            b"missing", sign_count=1, device_type=None, backed_up=None
        )


def test_passkey_service_registration_and_login_with_store(
    store, monkeypatch: pytest.MonkeyPatch
) -> None:
    passkeys = PasskeyService(
        config=PasskeyConfig(rp_id="localhost", rp_name="Demo", origin="http://localhost:8000"),
        challenges=MemoryChallengeStore(),
        credentials=store,
    )
    user = make_user()
    passkeys.begin_registration(flow_id="invite-1", user=user)

    monkeypatch.setattr(
        "my_auth.passkeys.verify_registration_response",
        lambda **kwargs: SimpleNamespace(
            credential_id=b"credential-1",
            credential_public_key=b"public-key",
            sign_count=0,
            credential_device_type="single_device",
            credential_backed_up=False,
        ),
    )
    passkeys.finish_registration(flow_id="invite-1", credential={"response": {"transports": ["internal"]}})

    assert store.get_user("u1") == user
    stored = store.get_credential(b"credential-1")
    assert stored is not None
    assert stored.transports == ["internal"]

    passkeys.begin_authentication(flow_id="login-1")
    monkeypatch.setattr(
        "my_auth.passkeys.verify_authentication_response",
        lambda **kwargs: SimpleNamespace(
            new_sign_count=1,
            credential_device_type="multi_device",
            credential_backed_up=True,
        ),
    )
    from my_auth.passkeys import bytes_to_b64url

    result = passkeys.finish_authentication(
        flow_id="login-1",
        credential={
            "id": bytes_to_b64url(b"credential-1"),
            "response": {"userHandle": bytes_to_b64url(b"handle-1")},
        },
    )

    assert result.user == user
    assert result.credential.sign_count == 1
    reloaded = store.get_credential(b"credential-1")
    assert reloaded is not None
    assert reloaded.sign_count == 1
    assert reloaded.backed_up is True
