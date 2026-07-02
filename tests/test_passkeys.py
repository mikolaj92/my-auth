from __future__ import annotations

from datetime import UTC, datetime, timedelta
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


def test_sqlite_store_pops_valid_challenge_with_user(tmp_path) -> None:
    store = SQLiteChallengeStore(tmp_path / "challenges.db")
    user = PasskeyUser(user_id="u1", user_handle=b"handle", name="mikolaj", display_name="Mikołaj")

    store.save(key="invite-1", kind="registration", challenge=b"abc", ttl_seconds=300, user=user)
    record = store.pop(key="invite-1", kind="registration")

    assert record.challenge == b"abc"
    assert record.kind == "registration"
    assert record.user == user


def test_sqlite_store_challenge_is_single_use(tmp_path) -> None:
    store = SQLiteChallengeStore(tmp_path / "challenges.db")
    store.save(key="login-1", kind="authentication", challenge=b"abc", ttl_seconds=300)

    store.pop(key="login-1", kind="authentication")

    with pytest.raises(ChallengeNotFound):
        store.pop(key="login-1", kind="authentication")


def test_sqlite_store_rejects_missing_challenge(tmp_path) -> None:
    store = SQLiteChallengeStore(tmp_path / "challenges.db")

    with pytest.raises(ChallengeNotFound):
        store.pop(key="never-saved", kind="authentication")


def test_sqlite_store_rejects_expired_challenge_and_consumes_it(tmp_path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = SQLiteChallengeStore(tmp_path / "challenges.db", now=lambda: now)
    store.save(key="flow", kind="authentication", challenge=b"abc", ttl_seconds=1)

    now += timedelta(seconds=2)

    with pytest.raises(ChallengeNotFound):
        store.pop(key="flow", kind="authentication")
    with pytest.raises(ChallengeNotFound):
        store.pop(key="flow", kind="authentication")


def test_sqlite_store_is_shared_between_instances_like_workers(tmp_path) -> None:
    path = tmp_path / "challenges.db"
    worker1 = SQLiteChallengeStore(path)
    worker2 = SQLiteChallengeStore(path)

    worker1.save(key="login-1", kind="authentication", challenge=b"abc", ttl_seconds=300)
    record = worker2.pop(key="login-1", kind="authentication")

    assert record.challenge == b"abc"
    with pytest.raises(ChallengeNotFound):
        worker1.pop(key="login-1", kind="authentication")


def test_sqlite_store_separates_kinds_for_same_key(tmp_path) -> None:
    store = SQLiteChallengeStore(tmp_path / "challenges.db")
    store.save(key="flow", kind="registration", challenge=b"reg", ttl_seconds=300)
    store.save(key="flow", kind="authentication", challenge=b"auth", ttl_seconds=300)

    assert store.pop(key="flow", kind="registration").challenge == b"reg"
    assert store.pop(key="flow", kind="authentication").challenge == b"auth"


def test_sqlite_store_cleanup_removes_only_expired(tmp_path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    store = SQLiteChallengeStore(tmp_path / "challenges.db", now=lambda: now)
    store.save(key="old", kind="authentication", challenge=b"old", ttl_seconds=1)
    store.save(key="fresh", kind="authentication", challenge=b"fresh", ttl_seconds=600)

    now += timedelta(seconds=2)

    assert store.cleanup_expired() == 1
    assert store.pop(key="fresh", kind="authentication").challenge == b"fresh"


def test_passkey_service_works_with_sqlite_challenge_store(tmp_path) -> None:
    passkeys = PasskeyService(
        config=PasskeyConfig(rp_id="localhost", rp_name="Demo", origin="http://localhost:8000"),
        challenges=SQLiteChallengeStore(tmp_path / "challenges.db"),
        credentials=MemoryCredentialStore(),
    )
    user = PasskeyUser(user_id="u1", user_handle=b"stable-user-handle", name="mikolaj")

    options = passkeys.begin_registration(flow_id="invite-1", user=user)

    assert options["rp"]["id"] == "localhost"
    record = passkeys.challenges.pop(key="invite-1", kind="registration")
    assert record.user == user


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
