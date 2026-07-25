from __future__ import annotations

from types import SimpleNamespace

import pytest

from my_auth import (
    ChallengeNotFound,
    CredentialCounterConflict,
    MemoryChallengeStore,
    MemoryCredentialStore,
    PasskeyConfig,
    PasskeyCredential,
    PasskeyService,
    PasskeyUser,
    VerifiedRegistration,
)


def test_memory_challenge_single_use_and_expiry() -> None:
    store = MemoryChallengeStore()
    store.save(
        key="flow", kind="authentication", challenge=b"challenge", ttl_seconds=300
    )
    assert store.pop(key="flow", kind="authentication").challenge == b"challenge"
    with pytest.raises(ChallengeNotFound):
        store.pop(key="flow", kind="authentication")


def test_registration_save_and_counter_cas() -> None:
    store = MemoryCredentialStore()
    user = PasskeyUser("u", b"handle", "name")
    credential = PasskeyCredential(b"credential", "u", b"public", sign_count=2)
    store.save_registration(VerifiedRegistration(user, credential))
    assert store.get_user_by_handle(b"handle") == user
    assert (
        store.compare_and_set_credential_after_login(
            b"credential",
            expected_sign_count=2,
            new_sign_count=3,
            device_type=None,
            backed_up=None,
        ).sign_count
        == 3
    )
    with pytest.raises(CredentialCounterConflict):
        store.compare_and_set_credential_after_login(
            b"credential",
            expected_sign_count=2,
            new_sign_count=4,
            device_type=None,
            backed_up=None,
        )


def test_verify_registration_is_persistence_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    challenges = MemoryChallengeStore()
    credentials = MemoryCredentialStore()
    service = PasskeyService(
        config=PasskeyConfig(
            rp_id="localhost", rp_name="Demo", origin="http://localhost:8000"
        ),
        challenges=challenges,
        credentials=credentials,
    )
    user = PasskeyUser("u", b"handle", "name")
    service.begin_registration(flow_id="flow", user=user)
    monkeypatch.setattr(
        "my_auth.passkeys.verify_registration_response",
        lambda **kwargs: SimpleNamespace(
            credential_id=b"id",
            credential_public_key=b"pk",
            sign_count=0,
            credential_device_type=None,
            credential_backed_up=None,
        ),
    )
    result = service.verify_registration(
        flow_id="flow", credential={"id": "aWQ=", "response": {}}
    )
    assert result.user == user
    assert credentials.get_user("u") is None
