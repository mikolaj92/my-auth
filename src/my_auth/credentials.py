from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeAlias

from .passkeys import CredentialNotFound, PasskeyCredential, PasskeyUser


class SQLiteCredentialStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if self.path.parent != Path(""):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def save_user(self, user: PasskeyUser) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO passkey_users (user_id, user_handle, name, display_name)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    user_handle = excluded.user_handle,
                    name = excluded.name,
                    display_name = excluded.display_name
                """,
                (user.user_id, user.user_handle, user.name, user.display_name),
            )

    def get_user(self, user_id: str) -> PasskeyUser | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT user_id, user_handle, name, display_name
                FROM passkey_users
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()
        return _user_from_row(row) if row is not None else None

    def get_user_by_handle(self, user_handle: bytes) -> PasskeyUser | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT user_id, user_handle, name, display_name
                FROM passkey_users
                WHERE user_handle = ?
                """,
                (user_handle,),
            ).fetchone()
        return _user_from_row(row) if row is not None else None

    def list_credentials_for_user(self, user_id: str) -> Iterable[PasskeyCredential]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT credential_id, user_id, public_key, sign_count, transports,
                       device_type, backed_up, label, created_at
                FROM passkey_credentials
                WHERE user_id = ?
                ORDER BY created_at DESC, credential_id ASC
                """,
                (user_id,),
            ).fetchall()
        return [_credential_from_row(row) for row in rows]

    def get_credential(self, credential_id: bytes) -> PasskeyCredential | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT credential_id, user_id, public_key, sign_count, transports,
                       device_type, backed_up, label, created_at
                FROM passkey_credentials
                WHERE credential_id = ?
                """,
                (credential_id,),
            ).fetchone()
        return _credential_from_row(row) if row is not None else None

    def save_credential(self, credential: PasskeyCredential) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO passkey_credentials (
                    credential_id,
                    user_id,
                    public_key,
                    sign_count,
                    transports,
                    device_type,
                    backed_up,
                    label,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(credential_id) DO UPDATE SET
                    user_id = excluded.user_id,
                    public_key = excluded.public_key,
                    sign_count = excluded.sign_count,
                    transports = excluded.transports,
                    device_type = excluded.device_type,
                    backed_up = excluded.backed_up,
                    label = excluded.label,
                    created_at = excluded.created_at
                """,
                (
                    credential.credential_id,
                    credential.user_id,
                    credential.public_key,
                    credential.sign_count,
                    json.dumps(credential.transports),
                    credential.device_type,
                    _bool_to_sqlite(credential.backed_up),
                    credential.label,
                    credential.created_at.isoformat(),
                ),
            )

    def update_credential_after_login(
        self,
        credential_id: bytes,
        *,
        sign_count: int,
        device_type: str | None,
        backed_up: bool | None,
    ) -> PasskeyCredential:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE passkey_credentials
                SET sign_count = ?, device_type = ?, backed_up = ?
                WHERE credential_id = ?
                """,
                (sign_count, device_type, _bool_to_sqlite(backed_up), credential_id),
            )
            if cursor.rowcount != 1:
                raise CredentialNotFound("unknown passkey credential")
            row = connection.execute(
                """
                SELECT credential_id, user_id, public_key, sign_count, transports,
                       device_type, backed_up, label, created_at
                FROM passkey_credentials
                WHERE credential_id = ?
                """,
                (credential_id,),
            ).fetchone()
        if row is None:
            raise CredentialNotFound("unknown passkey credential")
        return _credential_from_row(row)

    def delete_credential(self, credential_id: bytes, *, user_id: str | None = None) -> bool:
        with self._connect() as connection:
            if user_id is None:
                cursor = connection.execute(
                    "DELETE FROM passkey_credentials WHERE credential_id = ?",
                    (credential_id,),
                )
            else:
                cursor = connection.execute(
                    "DELETE FROM passkey_credentials WHERE credential_id = ? AND user_id = ?",
                    (credential_id, user_id),
                )
        return cursor.rowcount == 1

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS passkey_users (
                    user_id TEXT PRIMARY KEY,
                    user_handle BLOB NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    display_name TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS passkey_credentials (
                    credential_id BLOB PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES passkey_users(user_id),
                    public_key BLOB NOT NULL,
                    sign_count INTEGER NOT NULL DEFAULT 0,
                    transports TEXT,
                    device_type TEXT,
                    backed_up INTEGER,
                    label TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS ix_passkey_credentials_user_id
                ON passkey_credentials(user_id)
                """
            )


UserRow: TypeAlias = tuple[str, bytes, str, str | None]
CredentialRow: TypeAlias = tuple[
    bytes,
    str,
    bytes,
    int,
    str | None,
    str | None,
    int | None,
    str | None,
    str | None,
]


def _user_from_row(row: UserRow) -> PasskeyUser:
    user_id, user_handle, name, display_name = row
    return PasskeyUser(
        user_id=user_id,
        user_handle=user_handle,
        name=name,
        display_name=display_name,
    )


def _credential_from_row(row: CredentialRow) -> PasskeyCredential:
    credential_id, user_id, public_key, sign_count, transports, device_type, backed_up, label, created_at = row
    return PasskeyCredential(
        credential_id=credential_id,
        user_id=user_id,
        public_key=public_key,
        sign_count=sign_count,
        transports=json.loads(transports) if transports else [],
        device_type=device_type,
        backed_up=_bool_from_sqlite(backed_up),
        label=label,
        created_at=datetime.fromisoformat(created_at) if created_at else datetime.now(UTC),
    )


def _bool_to_sqlite(value: bool | None) -> int | None:
    if value is None:
        return None
    return 1 if value else 0


def _bool_from_sqlite(value: int | None) -> bool | None:
    if value is None:
        return None
    return bool(value)
