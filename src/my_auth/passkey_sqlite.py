from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterable
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from .passkey_errors import (
    ChallengeNotFound,
    CredentialCounterConflict,
    CredentialNotFound,
    PasskeyCredentialConflict,
    PasskeyUserConflict,
)
from .passkey_models import (
    ChallengeKind,
    ChallengeRecord,
    PasskeyCredential,
    PasskeyUser,
    RegistrationContext,
    VerifiedRegistration,
    b64url_to_bytes,
    bytes_to_b64url,
)

_CREDENTIAL_COLUMNS = "credential_id, user_id, public_key, sign_count, transports, device_type, backed_up, label, created_at"
_CHALLENGE_COLUMNS = (
    "challenge, kind, key, expires_at, user_id, user_handle, user_name, "
    "user_display_name, registration_kind, capability_id"
)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _sqlite_datetime(value: datetime) -> str:
    return _utc(value).isoformat()


def _sqlite_bool(value: bool | None) -> int | None:
    return None if value is None else int(value)


def _sqlite_user(row: Any) -> PasskeyUser | None:
    return (
        None
        if row is None
        else PasskeyUser(row[0], b64url_to_bytes(row[1]), row[2], row[3])
    )


def _sqlite_credential(row: Any) -> PasskeyCredential:
    return PasskeyCredential(
        b64url_to_bytes(row[0]),
        row[1],
        bytes(row[2]),
        int(row[3]),
        json.loads(row[4]) if row[4] else [],
        row[5],
        bool(row[6]) if row[6] is not None else None,
        row[7],
        datetime.fromisoformat(row[8]),
    )


def _sqlite_credential_values(c: PasskeyCredential) -> tuple[Any, ...]:
    return (
        bytes_to_b64url(c.credential_id),
        c.user_id,
        c.public_key,
        c.sign_count,
        json.dumps(c.transports),
        c.device_type,
        _sqlite_bool(c.backed_up),
        c.label,
        _sqlite_datetime(c.created_at),
    )


def _sqlite_challenge(row: Any) -> ChallengeRecord:
    user = (
        None
        if row[4] is None
        else PasskeyUser(row[4], b64url_to_bytes(row[5]), row[6], row[7])
    )
    return ChallengeRecord(
        bytes(row[0]),
        row[1],
        row[2],
        datetime.fromisoformat(row[3]),
        user,
        row[8],
        row[9],
    )


def _sqlite_challenge_values(r: ChallengeRecord) -> tuple[Any, ...]:
    u = r.user
    return (
        r.key,
        r.kind,
        r.challenge,
        _sqlite_datetime(r.expires_at),
        u.user_id if u else None,
        bytes_to_b64url(u.user_handle) if u else None,
        u.name if u else None,
        u.display_name if u else None,
        r.registration_kind,
        r.capability_id,
    )


class _SQLiteBase:
    def __init__(
        self,
        database: str | Path | sqlite3.Connection,
        *,
        transaction_mode: Literal["operation", "external"] = "operation",
    ) -> None:
        if transaction_mode not in {"operation", "external"}:
            raise ValueError("invalid transaction_mode")
        self._external = database if isinstance(database, sqlite3.Connection) else None
        self._path = None if self._external else str(database)
        if self._path == ":memory:":
            raise ValueError("path-mode :memory: is unsupported; provide a connection")
        if transaction_mode == "external":
            if self._external is None:
                raise RuntimeError(
                    "external transaction mode requires a caller-owned sqlite connection"
                )
            if not self._external.in_transaction:
                raise RuntimeError(
                    "external transaction mode requires an active caller transaction"
                )
            if self._external.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
                raise RuntimeError(
                    "external transaction mode requires PRAGMA foreign_keys=ON"
                )
        self.transaction_mode = transaction_mode
        if self._external is not None:
            check = self._external
        else:
            assert self._path is not None
            check = sqlite3.connect(self._path, timeout=30)
        try:
            from .sqlite_schema import inspect_sqlite_schema

            inspection = inspect_sqlite_schema(check)
            if inspection.state != "current":
                detail = "; ".join(inspection.diagnostics)
                if inspection.state == "legacy":
                    detail = "legacy schema requires migration"
                elif not detail:
                    detail = f"schema state is {inspection.state}"
                raise RuntimeError(f"my-auth schema is not current: {detail}")
        finally:
            if self._external is None:
                check.close()

    @contextmanager
    def _connection(self, *, mutation: bool = False, serialized: bool = False):
        if self._external is not None:
            conn = self._external
        else:
            assert self._path is not None
            conn = sqlite3.connect(self._path, timeout=30, check_same_thread=False)
        if self._external is None:
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        marker = None
        try:
            if mutation:
                if self.transaction_mode == "external":
                    if not conn.in_transaction:
                        raise RuntimeError(
                            "external transaction mode requires an active caller transaction"
                        )
                    if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
                        raise RuntimeError(
                            "external transaction mode requires PRAGMA foreign_keys=ON"
                        )
                    marker = "sp_" + bytes_to_b64url(
                        __import__("secrets").token_bytes(8)
                    ).replace("-", "_")
                    conn.execute(f"SAVEPOINT {marker}")
                else:
                    conn.execute("BEGIN IMMEDIATE" if serialized else "BEGIN")
            yield conn
            if mutation:
                if self.transaction_mode == "external":
                    conn.execute(f"RELEASE SAVEPOINT {marker}")
                else:
                    conn.commit()
        except Exception:
            if mutation:
                if self.transaction_mode == "external" and marker is not None:
                    conn.execute(f"ROLLBACK TO SAVEPOINT {marker}")
                    conn.execute(f"RELEASE SAVEPOINT {marker}")
                elif self.transaction_mode != "external":
                    conn.rollback()
            raise
        finally:
            if self._external is None:
                conn.close()


class SQLiteChallengeStore(_SQLiteBase):
    def __init__(
        self,
        database: str | Path | sqlite3.Connection,
        *,
        transaction_mode: Literal["operation", "external"] = "operation",
        now: Callable[[], datetime] | None = None,
    ) -> None:
        super().__init__(database, transaction_mode=transaction_mode)
        self._now = now or (lambda: datetime.now(UTC))

    def save(
        self,
        *,
        key: str,
        kind: ChallengeKind,
        challenge: bytes,
        ttl_seconds: int,
        user: PasskeyUser | None = None,
        registration_context: RegistrationContext | None = None,
    ) -> ChallengeRecord:
        if registration_context is not None:
            if kind != "registration" or user not in {None, registration_context.user}:
                raise ValueError("registration context does not match challenge")
            user = registration_context.user
        record = ChallengeRecord(
            challenge,
            kind,
            key,
            _utc(self._now() + timedelta(seconds=ttl_seconds)),
            user,
            registration_context.kind if registration_context else None,
            registration_context.capability_id if registration_context else None,
        )
        with self._connection(mutation=True) as conn:
            conn.execute(
                "INSERT INTO passkey_challenges(key,kind,challenge,expires_at,user_id,user_handle,user_name,user_display_name,registration_kind,capability_id) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(key,kind) DO UPDATE SET challenge=excluded.challenge,expires_at=excluded.expires_at,user_id=excluded.user_id,user_handle=excluded.user_handle,user_name=excluded.user_name,user_display_name=excluded.user_display_name,registration_kind=excluded.registration_kind,capability_id=excluded.capability_id",
                _sqlite_challenge_values(record),
            )
        return record

    def pop(self, *, key: str, kind: ChallengeKind) -> ChallengeRecord:
        with self._connection(mutation=True) as conn:
            row = conn.execute(
                f"DELETE FROM passkey_challenges WHERE key=? AND kind=? AND expires_at>? RETURNING {_CHALLENGE_COLUMNS}",
                (key, kind, _sqlite_datetime(self._now())),
            ).fetchone()
            if row is None:
                raise ChallengeNotFound(f"missing or expired {kind} challenge")
            return _sqlite_challenge(row)

    def cleanup_expired(self) -> int:
        with self._connection(mutation=True) as conn:
            return conn.execute(
                "DELETE FROM passkey_challenges WHERE expires_at<=?",
                (_sqlite_datetime(self._now()),),
            ).rowcount


class SQLiteCredentialStore(_SQLiteBase):
    def __init__(
        self,
        database: str | Path | sqlite3.Connection,
        *,
        transaction_mode: Literal["operation", "external"] = "operation",
    ) -> None:
        super().__init__(database, transaction_mode=transaction_mode)

    def save_registration(self, result: VerifiedRegistration) -> None:
        user, credential = result.user, result.credential
        if credential.user_id != user.user_id:
            raise PasskeyCredentialConflict("passkey credential ownership conflict")
        with self._connection(mutation=True) as conn:
            old = conn.execute(
                "SELECT user_id,user_handle,name,display_name FROM passkey_users WHERE user_id=?",
                (user.user_id,),
            ).fetchone()
            handle = conn.execute(
                "SELECT user_id FROM passkey_users WHERE user_handle=?",
                (bytes_to_b64url(user.user_handle),),
            ).fetchone()
            if (
                old is not None
                and _sqlite_user(old) != user
                or handle is not None
                and handle[0] != user.user_id
            ):
                raise PasskeyUserConflict("passkey user ownership conflict")
            existing = conn.execute(
                f"SELECT {_CREDENTIAL_COLUMNS} FROM passkey_credentials WHERE credential_id=?",
                (bytes_to_b64url(credential.credential_id),),
            ).fetchone()
            if existing is not None:
                current = _sqlite_credential(existing)
                if (
                    current.user_id != credential.user_id
                    or current.public_key != credential.public_key
                ):
                    raise PasskeyCredentialConflict(
                        "passkey credential ownership conflict"
                    )
            else:
                if old is None:
                    conn.execute(
                        "INSERT INTO passkey_users(user_id,user_handle,name,display_name) VALUES(?,?,?,?)",
                        (
                            user.user_id,
                            bytes_to_b64url(user.user_handle),
                            user.name,
                            user.display_name,
                        ),
                    )
                conn.execute(
                    f"INSERT INTO passkey_credentials({_CREDENTIAL_COLUMNS}) VALUES(?,?,?,?,?,?,?,?,?)",
                    _sqlite_credential_values(credential),
                )

    def get_user(self, user_id: str) -> PasskeyUser | None:
        with self._connection() as conn:
            return _sqlite_user(
                conn.execute(
                    "SELECT user_id,user_handle,name,display_name FROM passkey_users WHERE user_id=?",
                    (user_id,),
                ).fetchone()
            )

    def get_user_by_handle(self, user_handle: bytes) -> PasskeyUser | None:
        with self._connection() as conn:
            return _sqlite_user(
                conn.execute(
                    "SELECT user_id,user_handle,name,display_name FROM passkey_users WHERE user_handle=?",
                    (bytes_to_b64url(user_handle),),
                ).fetchone()
            )

    def list_credentials_for_user(self, user_id: str) -> Iterable[PasskeyCredential]:
        with self._connection() as conn:
            return [
                _sqlite_credential(row)
                for row in conn.execute(
                    f"SELECT {_CREDENTIAL_COLUMNS} FROM passkey_credentials WHERE user_id=? ORDER BY created_at,credential_id",
                    (user_id,),
                ).fetchall()
            ]

    def get_credential(self, credential_id: bytes) -> PasskeyCredential | None:
        with self._connection() as conn:
            row = conn.execute(
                f"SELECT {_CREDENTIAL_COLUMNS} FROM passkey_credentials WHERE credential_id=?",
                (bytes_to_b64url(credential_id),),
            ).fetchone()
            return _sqlite_credential(row) if row else None

    def compare_and_set_credential_after_login(
        self,
        credential_id: bytes,
        *,
        expected_sign_count: int,
        new_sign_count: int,
        device_type: str | None,
        backed_up: bool | None,
    ) -> PasskeyCredential:
        with self._connection(mutation=True) as conn:
            key = bytes_to_b64url(credential_id)
            row = conn.execute(
                f"SELECT {_CREDENTIAL_COLUMNS} FROM passkey_credentials WHERE credential_id=?",
                (key,),
            ).fetchone()
            if row is None:
                raise CredentialNotFound("unknown passkey credential")
            current = _sqlite_credential(row)
            if (
                expected_sign_count
                and current.sign_count != expected_sign_count
                or new_sign_count < current.sign_count
            ):
                raise CredentialCounterConflict(
                    "credential counter changed concurrently"
                )
            count = max(current.sign_count, new_sign_count)
            updated = conn.execute(
                "UPDATE passkey_credentials SET sign_count=?,device_type=?,backed_up=? WHERE credential_id=? AND (sign_count=? OR ?=0)",
                (
                    count,
                    device_type,
                    _sqlite_bool(backed_up),
                    key,
                    current.sign_count,
                    expected_sign_count,
                ),
            ).rowcount
            if not updated:
                raise CredentialCounterConflict(
                    "credential counter changed concurrently"
                )
            return _sqlite_credential(
                conn.execute(
                    f"SELECT {_CREDENTIAL_COLUMNS} FROM passkey_credentials WHERE credential_id=?",
                    (key,),
                ).fetchone()
            )

    def update_credential_label(
        self, credential_id: bytes, *, user_id: str, label: str | None
    ) -> PasskeyCredential | None:
        with self._connection(mutation=True) as conn:
            key = bytes_to_b64url(credential_id)
            if (
                conn.execute(
                    "UPDATE passkey_credentials SET label=? WHERE credential_id=? AND user_id=?",
                    (label, key, user_id),
                ).rowcount
                != 1
            ):
                return None
            row = conn.execute(
                f"SELECT {_CREDENTIAL_COLUMNS} FROM passkey_credentials WHERE credential_id=? AND user_id=?",
                (key, user_id),
            ).fetchone()
            return _sqlite_credential(row) if row else None

    def delete_credential(
        self,
        credential_id: bytes,
        *,
        user_id: str | None = None,
        require_remaining: bool = False,
    ) -> bool:
        with self._connection(mutation=True, serialized=require_remaining) as conn:
            key = bytes_to_b64url(credential_id)
            if require_remaining and self.transaction_mode == "external":
                # A deferred caller transaction must own the write lock before
                # reading the count, otherwise concurrent deletes can share a
                # stale snapshot and both remove the final credentials.
                conn.execute(
                    "UPDATE passkey_credentials SET credential_id=credential_id WHERE credential_id=?"
                    + (" AND user_id=?" if user_id is not None else ""),
                    (key,) if user_id is None else (key, user_id),
                )
            row = conn.execute(
                "SELECT user_id FROM passkey_credentials WHERE credential_id=?"
                + (" AND user_id=?" if user_id is not None else ""),
                (key,) if user_id is None else (key, user_id),
            ).fetchone()
            if row is None:
                return False
            if (
                require_remaining
                and conn.execute(
                    "SELECT COUNT(*) FROM passkey_credentials WHERE user_id=?",
                    (row[0],),
                ).fetchone()[0]
                <= 1
            ):
                return False
            return (
                conn.execute(
                    "DELETE FROM passkey_credentials WHERE credential_id=?"
                    + (" AND user_id=?" if user_id is not None else ""),
                    (key,) if user_id is None else (key, user_id),
                ).rowcount
                > 0
            )
