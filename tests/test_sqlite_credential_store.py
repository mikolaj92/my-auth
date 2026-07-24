from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from my_auth import PasskeyCredential, PasskeyUser, SQLiteCredentialStore


def test_persists_users_and_credentials_across_instances(tmp_path: Path) -> None:
    # Given
    db_path = tmp_path / "passkeys.sqlite3"
    user = PasskeyUser(user_id="u1", user_handle=b"handle", name="mikolaj", display_name="Mikołaj")
    created_at = datetime(2026, 1, 1, tzinfo=UTC)
    credential = PasskeyCredential(
        credential_id=b"credential-id",
        user_id="u1",
        public_key=b"public-key",
        sign_count=7,
        transports=["internal", "usb"],
        device_type="multi_device",
        backed_up=True,
        label="Laptop",
        created_at=created_at,
    )
    store = SQLiteCredentialStore(db_path)
    store.save_user(user)
    store.save_credential(credential)

    # When
    reopened = SQLiteCredentialStore(db_path)

    # Then
    assert reopened.get_user("u1") == user
    assert reopened.get_user_by_handle(b"handle") == user
    assert reopened.get_credential(b"credential-id") == credential
    assert list(reopened.list_credentials_for_user("u1")) == [credential]


def test_keeps_other_users_credential_when_user_id_does_not_match(tmp_path: Path) -> None:
    # Given
    store = SQLiteCredentialStore(tmp_path / "passkeys.sqlite3")
    store.save_user(PasskeyUser(user_id="u1", user_handle=b"handle-1", name="one"))
    store.save_user(PasskeyUser(user_id="u2", user_handle=b"handle-2", name="two"))
    store.save_credential(PasskeyCredential(credential_id=b"laptop", user_id="u2", public_key=b"pk2"))

    # When
    deleted = store.delete_credential(b"laptop", user_id="u1")

    # Then
    assert deleted is False
    assert store.get_credential(b"laptop") is not None


def test_deletes_matching_credential_when_user_id_matches(tmp_path: Path) -> None:
    # Given
    store = SQLiteCredentialStore(tmp_path / "passkeys.sqlite3")
    store.save_user(PasskeyUser(user_id="u1", user_handle=b"handle", name="one"))
    store.save_credential(PasskeyCredential(credential_id=b"phone", user_id="u1", public_key=b"pk"))

    # When
    deleted = store.delete_credential(b"phone", user_id="u1")

    # Then
    assert deleted is True
    assert store.get_credential(b"phone") is None


def test_updates_login_metadata(tmp_path: Path) -> None:
    # Given
    store = SQLiteCredentialStore(tmp_path / "passkeys.sqlite3")
    store.save_user(PasskeyUser(user_id="u1", user_handle=b"handle", name="mikolaj"))
    store.save_credential(PasskeyCredential(credential_id=b"credential-id", user_id="u1", public_key=b"pk"))

    # When
    updated = store.update_credential_after_login(
        b"credential-id",
        sign_count=42,
        device_type="multi_device",
        backed_up=True,
    )

    # Then
    assert updated.sign_count == 42
    assert updated.device_type == "multi_device"
    assert updated.backed_up is True
