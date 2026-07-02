from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from my_auth import (
    ChallengeNotFound,
    MemoryChallengeStore,
    MemoryCredentialStore,
    PasskeyConfig,
    PasskeyCredential,
    PasskeyService,
    PasskeyUser,
    SQLiteChallengeStore,
    SQLiteCredentialStore,
    UserHandleMismatch,
)
from my_auth.passkeys import bytes_to_b64url


def service() -> tuple[PasskeyService, MemoryChallengeStore, MemoryCredentialStore]:
    challenges = MemoryChallengeStore()
    credentials = MemoryCredentialStore()
    return (
        PasskeyService(
            config=PasskeyConfig(rp_id="localhost", rp_name="Demo", origin="http://localhost:8000"),
            challenges=challenges,
            credentials=credentials,
        ),
        challenges,
        credentials,
    )


def test_begin_registration_requires_resident_key_and_saves_single_use_challenge() -> None:
    passkeys, challenges, _ = service()
    user = PasskeyUser(user_id="u1", user_handle=b"stable-user-handle", name="mikolaj")

    options = passkeys.begin_registration(flow_id="invite-1", user=user)

    assert options["rp"]["id"] == "localhost"
    assert options["user"]["id"] == bytes_to_b64url(user.user_handle)
    assert options["authenticatorSelection"]["residentKey"] == "required"
    assert options["authenticatorSelection"]["userVerification"] == "required"
    record = challenges.pop(key="invite-1", kind="registration")
    assert record.user == user
    with pytest.raises(ChallengeNotFound):
        challenges.pop(key="invite-1", kind="registration")


def test_challenge_store_expires_records() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = MemoryChallengeStore(now=lambda: now)
    store.save(key="flow", kind="authentication", challenge=b"abc", ttl_seconds=1)

    now += timedelta(seconds=2)

    with pytest.raises(ChallengeNotFound):
        store.pop(key="flow", kind="authentication")


def test_sqlite_challenge_store_atomically_consumes_across_connections(tmp_path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    database = tmp_path / "challenges.sqlite"
    writer = SQLiteChallengeStore(database, now=lambda: now)
    reader = SQLiteChallengeStore(database, now=lambda: now)
    user = PasskeyUser(user_id="u1", user_handle=b"handle", name="mikolaj")

    writer.save(key="flow", kind="registration", challenge=b"abc", ttl_seconds=300, user=user)

    record = reader.pop(key="flow", kind="registration")

    assert record.challenge == b"abc"
    assert record.user == user
    with pytest.raises(ChallengeNotFound):
        writer.pop(key="flow", kind="registration")


def test_sqlite_challenge_store_keeps_kinds_separate(tmp_path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = SQLiteChallengeStore(tmp_path / "challenges.sqlite", now=lambda: now)
    store.save(key="flow", kind="authentication", challenge=b"abc", ttl_seconds=300)

    with pytest.raises(ChallengeNotFound):
        store.pop(key="flow", kind="registration")

    assert store.pop(key="flow", kind="authentication").challenge == b"abc"


def test_sqlite_challenge_store_rejects_and_cleans_up_expired_records(tmp_path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = SQLiteChallengeStore(tmp_path / "challenges.sqlite", now=lambda: now)
    store.save(key="expired", kind="authentication", challenge=b"old", ttl_seconds=1)
    store.save(key="active", kind="authentication", challenge=b"new", ttl_seconds=300)

    now += timedelta(seconds=2)

    assert store.cleanup_expired() == 1
    with pytest.raises(ChallengeNotFound):
        store.pop(key="expired", kind="authentication")
    assert store.pop(key="active", kind="authentication").challenge == b"new"


def test_sqlite_challenge_store_persists_registration_records_across_instances(tmp_path: Path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    db_path = tmp_path / "passkey-challenges.sqlite3"
    user = PasskeyUser(user_id="u1", user_handle=b"stable-user-handle", name="mikolaj", display_name="Mikołaj")

    SQLiteChallengeStore(db_path, now=lambda: now).save(
        key="register-1",
        kind="registration",
        challenge=b"challenge-bytes",
        ttl_seconds=300,
        user=user,
    )
    store = SQLiteChallengeStore(db_path, now=lambda: now)

    record = store.pop(key="register-1", kind="registration")

    assert record.challenge == b"challenge-bytes"
    assert record.user == user
    with pytest.raises(ChallengeNotFound):
        store.pop(key="register-1", kind="registration")


def test_sqlite_challenge_store_keeps_registration_and_authentication_challenges_isolated(tmp_path: Path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = SQLiteChallengeStore(tmp_path / "passkey-challenges.sqlite3", now=lambda: now)
    store.save(key="flow", kind="registration", challenge=b"registration", ttl_seconds=300)

    with pytest.raises(ChallengeNotFound):
        store.pop(key="flow", kind="authentication")

    record = store.pop(key="flow", kind="registration")
    assert record.challenge == b"registration"


def test_sqlite_challenge_store_deletes_expired_records_on_cleanup(tmp_path: Path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = SQLiteChallengeStore(tmp_path / "passkey-challenges.sqlite3", now=lambda: now)
    store.save(key="expired", kind="authentication", challenge=b"old", ttl_seconds=1)
    store.save(key="active", kind="authentication", challenge=b"fresh", ttl_seconds=10)

    now += timedelta(seconds=2)

    assert store.cleanup_expired() == 1
    with pytest.raises(ChallengeNotFound):
        store.pop(key="expired", kind="authentication")
    assert store.pop(key="active", kind="authentication").challenge == b"fresh"


def test_finish_registration_verifies_and_saves_user_and_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    passkeys, _, credentials = service()
    user = PasskeyUser(user_id="u1", user_handle=b"handle", name="mikolaj")
    passkeys.begin_registration(flow_id="invite-1", user=user)

    def fake_verify_registration_response(**kwargs):
        assert kwargs["expected_rp_id"] == "localhost"
        assert kwargs["expected_origin"] == "http://localhost:8000"
        assert kwargs["require_user_verification"] is True
        return SimpleNamespace(
            credential_id=b"credential-id",
            credential_public_key=b"public-key",
            sign_count=0,
            credential_device_type="single_device",
            credential_backed_up=False,
        )

    monkeypatch.setattr("my_auth.passkeys.verify_registration_response", fake_verify_registration_response)

    credential = passkeys.finish_registration(
        flow_id="invite-1",
        credential={"response": {"transports": ["internal"]}},
    )

    assert credentials.get_user("u1") == user
    assert credentials.get_credential(b"credential-id") == credential
    assert credential.transports == ["internal"]
    assert credential.public_key == b"public-key"


def test_begin_authentication_is_username_less_by_default() -> None:
    passkeys, challenges, _ = service()

    options = passkeys.begin_authentication(flow_id="login-1")

    assert options["rpId"] == "localhost"
    assert options["allowCredentials"] == []
    assert options["userVerification"] == "required"
    assert challenges.pop(key="login-1", kind="authentication").kind == "authentication"


def test_finish_authentication_updates_sign_count(monkeypatch: pytest.MonkeyPatch) -> None:
    passkeys, challenges, credentials = service()
    user = PasskeyUser(user_id="u1", user_handle=b"handle", name="mikolaj")
    credential = PasskeyCredential(
        credential_id=b"credential-id",
        user_id="u1",
        public_key=b"public-key",
        sign_count=7,
    )
    credentials.save_user(user)
    credentials.save_credential(credential)
    challenges.save(key="login-1", kind="authentication", challenge=b"challenge", ttl_seconds=300)

    def fake_verify_authentication_response(**kwargs):
        assert kwargs["expected_challenge"] == b"challenge"
        assert kwargs["credential_public_key"] == b"public-key"
        assert kwargs["credential_current_sign_count"] == 7
        return SimpleNamespace(
            new_sign_count=8,
            credential_device_type="multi_device",
            credential_backed_up=True,
        )

    monkeypatch.setattr("my_auth.passkeys.verify_authentication_response", fake_verify_authentication_response)

    result = passkeys.finish_authentication(
        flow_id="login-1",
        credential={
            "id": bytes_to_b64url(b"credential-id"),
            "response": {"userHandle": bytes_to_b64url(b"handle")},
        },
    )

    assert result.user == user
    assert result.credential.sign_count == 8
    assert result.credential.backed_up is True


def test_finish_authentication_rejects_user_handle_mismatch() -> None:
    passkeys, challenges, credentials = service()
    credentials.save_user(PasskeyUser(user_id="u1", user_handle=b"handle", name="mikolaj"))
    credentials.save_credential(PasskeyCredential(credential_id=b"credential-id", user_id="u1", public_key=b"pk"))
    challenges.save(key="login-1", kind="authentication", challenge=b"challenge", ttl_seconds=300)

    with pytest.raises(UserHandleMismatch):
        passkeys.finish_authentication(
            flow_id="login-1",
            credential={
                "id": bytes_to_b64url(b"credential-id"),
                "response": {"userHandle": bytes_to_b64url(b"other")},
            },
        )


def test_config_rejects_client_supplied_origin_as_rp_id() -> None:
    with pytest.raises(ValueError, match="rp_id"):
        PasskeyConfig(rp_id="https://example.com", rp_name="Demo", origin="https://example.com")


def test_config_rejects_fake_localhost_http_origin() -> None:
    with pytest.raises(ValueError, match="origin"):
        PasskeyConfig(rp_id="localhost", rp_name="Demo", origin="http://localhost.evil.com")


def test_memory_store_allows_multiple_passkeys_per_user() -> None:
    store = MemoryCredentialStore()
    user = PasskeyUser(user_id="u1", user_handle=b"handle", name="mikolaj")

    store.save_user(user)
    store.save_credential(PasskeyCredential(credential_id=b"phone", user_id="u1", public_key=b"pk1"))
    store.save_credential(PasskeyCredential(credential_id=b"laptop", user_id="u1", public_key=b"pk2"))

    assert {credential.credential_id for credential in store.list_credentials_for_user("u1")} == {
        b"phone",
        b"laptop",
    }


def test_sqlite_credential_store_persists_full_credential_lifecycle(tmp_path) -> None:
    database = tmp_path / "passkeys.sqlite"
    store = SQLiteCredentialStore(database)
    user = PasskeyUser(user_id="u1", user_handle=b"handle", name="mikolaj", display_name="Mikołaj")
    created_at = datetime(2026, 1, 1, tzinfo=UTC)

    store.save_user(user)
    store.save_credential(
        PasskeyCredential(
            credential_id=b"phone",
            user_id="u1",
            public_key=b"pk1",
            sign_count=3,
            transports=["internal"],
            device_type="single_device",
            backed_up=False,
            label="Phone",
            created_at=created_at,
        )
    )
    store.save_credential(
        PasskeyCredential(
            credential_id=b"laptop",
            user_id="u1",
            public_key=b"pk2",
            created_at=created_at + timedelta(seconds=1),
        )
    )
    store.close()

    reopened = SQLiteCredentialStore(database)

    assert reopened.get_user("u1") == user
    assert reopened.get_user_by_handle(b"handle") == user
    assert [credential.credential_id for credential in reopened.list_credentials_for_user("u1")] == [
        b"phone",
        b"laptop",
    ]
    updated = reopened.update_credential_after_login(
        b"phone",
        sign_count=4,
        device_type="multi_device",
        backed_up=True,
    )
    assert updated.sign_count == 4
    assert updated.backed_up is True
    assert updated.label == "Phone"
    assert reopened.delete_credential(b"laptop", user_id="other") is False
    assert reopened.delete_credential(b"laptop", user_id="u1") is True
    assert reopened.get_credential(b"laptop") is None
