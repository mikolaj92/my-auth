from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from .passkeys import CredentialNotFound, PasskeyCredential, PasskeyUser

SQLITE_SCHEMA = """\
CREATE TABLE IF NOT EXISTS passkey_users (
    user_id TEXT PRIMARY KEY,
    user_handle BLOB NOT NULL UNIQUE,
    name TEXT NOT NULL,
    display_name TEXT
);

CREATE TABLE IF NOT EXISTS passkey_credentials (
    credential_id BLOB PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES passkey_users(user_id),
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    transports TEXT NOT NULL DEFAULT '[]',
    device_type TEXT,
    backed_up INTEGER,
    label TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_passkey_credentials_user_id
    ON passkey_credentials (user_id);
"""


def transports_to_json(transports: Iterable[str]) -> str:
    return json.dumps(list(transports))


def transports_from_json(value: str | None) -> list[str]:
    if not value:
        return []
    return [str(item) for item in json.loads(value)]


def backed_up_to_int(backed_up: bool | None) -> int | None:
    return None if backed_up is None else int(backed_up)


def backed_up_from_int(value: int | None) -> bool | None:
    return None if value is None else bool(value)


def created_at_to_iso(created_at: datetime) -> str:
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    return created_at.isoformat()


def created_at_from_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


def user_to_row(user: PasskeyUser) -> dict[str, Any]:
    return {
        "user_id": user.user_id,
        "user_handle": user.user_handle,
        "name": user.name,
        "display_name": user.display_name,
    }


def user_from_row(row: Any) -> PasskeyUser:
    return PasskeyUser(
        user_id=row["user_id"],
        user_handle=bytes(row["user_handle"]),
        name=row["name"],
        display_name=row["display_name"],
    )


def credential_to_row(credential: PasskeyCredential) -> dict[str, Any]:
    return {
        "credential_id": credential.credential_id,
        "user_id": credential.user_id,
        "public_key": credential.public_key,
        "sign_count": credential.sign_count,
        "transports": transports_to_json(credential.transports),
        "device_type": credential.device_type,
        "backed_up": backed_up_to_int(credential.backed_up),
        "label": credential.label,
        "created_at": created_at_to_iso(credential.created_at),
    }


def credential_from_row(row: Any) -> PasskeyCredential:
    return PasskeyCredential(
        credential_id=bytes(row["credential_id"]),
        user_id=row["user_id"],
        public_key=bytes(row["public_key"]),
        sign_count=row["sign_count"],
        transports=transports_from_json(row["transports"]),
        device_type=row["device_type"],
        backed_up=backed_up_from_int(row["backed_up"]),
        label=row["label"],
        created_at=created_at_from_iso(row["created_at"]),
    )


class SQLiteCredentialStore:
    """CredentialStore backed by sqlite3 using the standard passkey schema."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.connection.row_factory = sqlite3.Row

    def create_tables(self) -> None:
        with self.connection:
            self.connection.executescript(SQLITE_SCHEMA)

    def save_user(self, user: PasskeyUser) -> None:
        row = user_to_row(user)
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO passkey_users (user_id, user_handle, name, display_name)
                VALUES (:user_id, :user_handle, :name, :display_name)
                ON CONFLICT (user_id) DO UPDATE SET
                    user_handle = excluded.user_handle,
                    name = excluded.name,
                    display_name = excluded.display_name
                """,
                row,
            )

    def get_user(self, user_id: str) -> PasskeyUser | None:
        row = self.connection.execute(
            "SELECT * FROM passkey_users WHERE user_id = ?", (user_id,)
        ).fetchone()
        return user_from_row(row) if row else None

    def get_user_by_handle(self, user_handle: bytes) -> PasskeyUser | None:
        row = self.connection.execute(
            "SELECT * FROM passkey_users WHERE user_handle = ?", (user_handle,)
        ).fetchone()
        return user_from_row(row) if row else None

    def list_credentials_for_user(self, user_id: str) -> list[PasskeyCredential]:
        rows = self.connection.execute(
            "SELECT * FROM passkey_credentials WHERE user_id = ? ORDER BY created_at",
            (user_id,),
        ).fetchall()
        return [credential_from_row(row) for row in rows]

    def get_credential(self, credential_id: bytes) -> PasskeyCredential | None:
        row = self.connection.execute(
            "SELECT * FROM passkey_credentials WHERE credential_id = ?",
            (credential_id,),
        ).fetchone()
        return credential_from_row(row) if row else None

    def save_credential(self, credential: PasskeyCredential) -> None:
        row = credential_to_row(credential)
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO passkey_credentials (
                    credential_id, user_id, public_key, sign_count,
                    transports, device_type, backed_up, label, created_at
                )
                VALUES (
                    :credential_id, :user_id, :public_key, :sign_count,
                    :transports, :device_type, :backed_up, :label, :created_at
                )
                ON CONFLICT (credential_id) DO UPDATE SET
                    user_id = excluded.user_id,
                    public_key = excluded.public_key,
                    sign_count = excluded.sign_count,
                    transports = excluded.transports,
                    device_type = excluded.device_type,
                    backed_up = excluded.backed_up,
                    label = excluded.label
                """,
                row,
            )

    def update_credential_after_login(
        self,
        credential_id: bytes,
        *,
        sign_count: int,
        device_type: str | None,
        backed_up: bool | None,
    ) -> PasskeyCredential:
        with self.connection:
            cursor = self.connection.execute(
                """
                UPDATE passkey_credentials
                SET sign_count = ?, device_type = ?, backed_up = ?
                WHERE credential_id = ?
                """,
                (sign_count, device_type, backed_up_to_int(backed_up), credential_id),
            )
        if cursor.rowcount == 0:
            raise CredentialNotFound("unknown passkey credential")
        credential = self.get_credential(credential_id)
        assert credential is not None
        return credential
