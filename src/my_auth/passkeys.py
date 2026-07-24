from __future__ import annotations

import json
import sqlite3
import threading
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Callable, Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.parse import urlparse

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

ChallengeKind = Literal["registration", "authentication"]


class ChallengeNotFound(Exception): ...


class CredentialNotFound(Exception): ...


class UserHandleMismatch(Exception): ...


class PasskeyUserConflict(Exception): ...


class PasskeyCredentialConflict(Exception): ...


class CredentialCounterConflict(Exception): ...


def bytes_to_b64url(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_to_bytes(value: str) -> bytes:
    return urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))


def _enum_value(value: Any) -> str | None:
    if value is None:
        return None
    return getattr(value, "value", str(value))


def _json_options(options: Any) -> dict[str, Any]:
    return json.loads(options_to_json(options))


def _credential_id_from_response(credential: Mapping[str, Any]) -> bytes:
    value = credential.get("rawId") or credential.get("id")
    if not value:
        raise CredentialNotFound("credential response has no id/rawId")
    return b64url_to_bytes(str(value))


def _user_handle_from_response(credential: Mapping[str, Any]) -> bytes | None:
    value = (credential.get("response") or {}).get("userHandle")
    return b64url_to_bytes(value) if value else None


def _transports_from_response(credential: Mapping[str, Any]) -> list[str]:
    values = (credential.get("response") or {}).get("transports") or []
    return [str(getattr(value, "value", value)) for value in values]


def _origin_allowed(origin: str) -> bool:
    parsed = urlparse(origin)
    if (
        parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not parsed.hostname
    ):
        return False
    try:
        parsed.port
    except ValueError:
        return False
    return parsed.scheme == "https" or (
        parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    )


@dataclass(frozen=True)
class PasskeyConfig:
    rp_id: str
    rp_name: str
    origin: str
    timeout_ms: int = 60_000
    challenge_ttl_seconds: int = 300
    user_verification: Literal["required", "preferred", "discouraged"] = "required"

    def __post_init__(self) -> None:
        for name in ("rp_id", "rp_name", "origin"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
            if value != value.strip():
                raise ValueError(f"{name} must not have surrounding whitespace")
        parsed = urlparse(self.origin)
        host = parsed.hostname or ""
        if (
            "://" in self.rp_id
            or "/" in self.rp_id
            or ":" in self.rp_id
            or self.rp_id.lower() != self.rp_id
        ):
            raise ValueError("rp_id must be a lowercase hostname only")
        if not _origin_allowed(self.origin):
            raise ValueError(
                "origin must be https:// in production; http is only allowed for localhost"
            )
        if host != self.rp_id and not host.endswith("." + self.rp_id):
            raise ValueError("rp_id must equal or be a suffix of the origin hostname")
        if self.timeout_ms <= 0 or self.challenge_ttl_seconds <= 0:
            raise ValueError("timeout_ms and challenge_ttl_seconds must be positive")
        if self.user_verification not in {"required", "preferred", "discouraged"}:
            raise ValueError("invalid user_verification")

    @property
    def user_verification_requirement(self) -> UserVerificationRequirement:
        return UserVerificationRequirement(self.user_verification)

    @property
    def require_user_verification(self) -> bool:
        return self.user_verification == "required"


@dataclass(frozen=True)
class PasskeyUser:
    user_id: str
    user_handle: bytes
    name: str
    display_name: str | None = None

    @property
    def user_handle_b64url(self) -> str:
        return bytes_to_b64url(self.user_handle)


@dataclass
class PasskeyCredential:
    credential_id: bytes
    user_id: str
    public_key: bytes
    sign_count: int = 0
    transports: list[str] = field(default_factory=list)
    device_type: str | None = None
    backed_up: bool | None = None
    label: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def id_b64url(self) -> str:
        return bytes_to_b64url(self.credential_id)


@dataclass(frozen=True)
class ChallengeRecord:
    challenge: bytes
    kind: ChallengeKind
    key: str
    expires_at: datetime
    user: PasskeyUser | None = None


@dataclass(frozen=True)
class AuthenticationResult:
    user: PasskeyUser
    credential: PasskeyCredential


@dataclass(frozen=True)
class VerifiedRegistration:
    user: PasskeyUser
    credential: PasskeyCredential


class CredentialStore(Protocol):
    def save_registration(self, result: VerifiedRegistration) -> None: ...
    def get_user(self, user_id: str) -> PasskeyUser | None: ...
    def get_user_by_handle(self, user_handle: bytes) -> PasskeyUser | None: ...
    def list_credentials_for_user(
        self, user_id: str
    ) -> Iterable[PasskeyCredential]: ...
    def get_credential(self, credential_id: bytes) -> PasskeyCredential | None: ...
    def compare_and_set_credential_after_login(
        self,
        credential_id: bytes,
        *,
        expected_sign_count: int,
        new_sign_count: int,
        device_type: str | None,
        backed_up: bool | None,
    ) -> PasskeyCredential: ...
    def delete_credential(
        self,
        credential_id: bytes,
        *,
        user_id: str | None = None,
        require_remaining: bool = False,
    ) -> bool: ...


class ChallengeStore(Protocol):
    def save(
        self,
        *,
        key: str,
        kind: ChallengeKind,
        challenge: bytes,
        ttl_seconds: int,
        user: PasskeyUser | None = None,
    ) -> ChallengeRecord: ...
    def pop(self, *, key: str, kind: ChallengeKind) -> ChallengeRecord: ...


PASSKEY_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS passkey_users (
 user_id TEXT PRIMARY KEY, user_handle TEXT NOT NULL UNIQUE, name TEXT NOT NULL, display_name TEXT
);
CREATE TABLE IF NOT EXISTS passkey_credentials (
 credential_id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES passkey_users(user_id) ON DELETE CASCADE,
 public_key BLOB NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0, transports TEXT, device_type TEXT,
 backed_up INTEGER, label TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_passkey_credentials_user_id ON passkey_credentials(user_id);
"""
PASSKEY_SQLITE_CHALLENGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS passkey_challenges (
 key TEXT NOT NULL, kind TEXT NOT NULL, challenge BLOB NOT NULL, expires_at TEXT NOT NULL,
 user_id TEXT, user_handle TEXT, user_name TEXT, user_display_name TEXT, PRIMARY KEY (key, kind)
);
CREATE INDEX IF NOT EXISTS idx_passkey_challenges_expires_at ON passkey_challenges(expires_at);
"""
_CREDENTIAL_COLUMNS = "credential_id, user_id, public_key, sign_count, transports, device_type, backed_up, label, created_at"
_CHALLENGE_COLUMNS = "challenge, kind, key, expires_at, user_id, user_handle, user_name, user_display_name"


class MemoryChallengeStore:
    def __init__(self, *, now: Callable[[], datetime] | None = None) -> None:
        self._records: dict[tuple[str, ChallengeKind], ChallengeRecord] = {}
        self._now = now or (lambda: datetime.now(UTC))

    def save(
        self,
        *,
        key: str,
        kind: ChallengeKind,
        challenge: bytes,
        ttl_seconds: int,
        user: PasskeyUser | None = None,
    ) -> ChallengeRecord:
        record = ChallengeRecord(
            challenge, kind, key, self._now() + timedelta(seconds=ttl_seconds), user
        )
        self._records[(key, kind)] = record
        return record

    def pop(self, *, key: str, kind: ChallengeKind) -> ChallengeRecord:
        record = self._records.pop((key, kind), None)
        if record is None or record.expires_at <= self._now():
            raise ChallengeNotFound(f"missing or expired {kind} challenge")
        return record

    def cleanup_expired(self) -> int:
        now = self._now()
        expired = [
            key for key, value in self._records.items() if value.expires_at <= now
        ]
        for key in expired:
            del self._records[key]
        return len(expired)


class MemoryCredentialStore:
    def __init__(self) -> None:
        self.users: dict[str, PasskeyUser] = {}
        self.users_by_handle: dict[bytes, str] = {}
        self.credentials: dict[bytes, PasskeyCredential] = {}
        self._lock = threading.RLock()

    def save_registration(self, result: VerifiedRegistration) -> None:
        with self._lock:
            user, credential = result.user, result.credential
            if credential.user_id != user.user_id:
                raise PasskeyCredentialConflict("passkey credential ownership conflict")
            old = self.users.get(user.user_id)
            by_handle = self.users_by_handle.get(user.user_handle)
            if (old is not None and old != user) or (
                by_handle is not None and by_handle != user.user_id
            ):
                raise PasskeyUserConflict("passkey user ownership conflict")
            existing = self.credentials.get(credential.credential_id)
            if existing is not None and (
                existing.user_id != credential.user_id
                or existing.public_key != credential.public_key
            ):
                raise PasskeyCredentialConflict("passkey credential ownership conflict")
            self.users[user.user_id] = user
            self.users_by_handle[user.user_handle] = user.user_id
            self.credentials.setdefault(credential.credential_id, credential)

    def get_user(self, user_id: str) -> PasskeyUser | None:
        return self.users.get(user_id)

    def get_user_by_handle(self, user_handle: bytes) -> PasskeyUser | None:
        with self._lock:
            user_id = self.users_by_handle.get(user_handle)
            return self.users.get(user_id) if user_id else None

    def list_credentials_for_user(self, user_id: str) -> Iterable[PasskeyCredential]:
        with self._lock:
            return [c for c in self.credentials.values() if c.user_id == user_id]

    def get_credential(self, credential_id: bytes) -> PasskeyCredential | None:
        return self.credentials.get(credential_id)

    def compare_and_set_credential_after_login(
        self,
        credential_id: bytes,
        *,
        expected_sign_count: int,
        new_sign_count: int,
        device_type: str | None,
        backed_up: bool | None,
    ) -> PasskeyCredential:
        with self._lock:
            credential = self.credentials.get(credential_id)
            if credential is None:
                raise CredentialNotFound("unknown passkey credential")
            if expected_sign_count and credential.sign_count != expected_sign_count:
                raise CredentialCounterConflict(
                    "credential counter changed concurrently"
                )
            if new_sign_count < credential.sign_count:
                raise CredentialCounterConflict("credential counter cannot regress")
            credential.sign_count = max(credential.sign_count, new_sign_count)
            credential.device_type = device_type
            credential.backed_up = backed_up
            return credential

    def delete_credential(
        self,
        credential_id: bytes,
        *,
        user_id: str | None = None,
        require_remaining: bool = False,
    ) -> bool:
        with self._lock:
            c = self.credentials.get(credential_id)
            if c is None or user_id is not None and c.user_id != user_id:
                return False
            if (
                require_remaining
                and sum(
                    credential.user_id == c.user_id
                    for credential in self.credentials.values()
                )
                <= 1
            ):
                return False
            del self.credentials[credential_id]
            return True


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
        bytes(row[0]), row[1], row[2], datetime.fromisoformat(row[3]), user
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
    ) -> ChallengeRecord:
        record = ChallengeRecord(
            challenge,
            kind,
            key,
            _utc(self._now() + timedelta(seconds=ttl_seconds)),
            user,
        )
        with self._connection(mutation=True) as conn:
            conn.execute(
                "INSERT INTO passkey_challenges(key,kind,challenge,expires_at,user_id,user_handle,user_name,user_display_name) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(key,kind) DO UPDATE SET challenge=excluded.challenge,expires_at=excluded.expires_at,user_id=excluded.user_id,user_handle=excluded.user_handle,user_name=excluded.user_name,user_display_name=excluded.user_display_name",
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


class PasskeyService:
    def __init__(
        self,
        *,
        config: PasskeyConfig,
        challenges: ChallengeStore,
        credentials: CredentialStore,
    ) -> None:
        self.config, self.challenges, self.credentials = config, challenges, credentials

    def begin_registration(self, *, flow_id: str, user: PasskeyUser) -> dict[str, Any]:
        existing = [
            PublicKeyCredentialDescriptor(id=c.credential_id)
            for c in self.credentials.list_credentials_for_user(user.user_id)
        ]
        options = generate_registration_options(
            rp_id=self.config.rp_id,
            rp_name=self.config.rp_name,
            user_name=user.name,
            user_id=user.user_handle,
            user_display_name=user.display_name or user.name,
            timeout=self.config.timeout_ms,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=self.config.user_verification_requirement,
            ),
            exclude_credentials=existing,
        )
        self.challenges.save(
            key=flow_id,
            kind="registration",
            challenge=options.challenge,
            ttl_seconds=self.config.challenge_ttl_seconds,
            user=user,
        )
        return _json_options(options)

    def verify_registration(
        self, *, flow_id: str, credential: Mapping[str, Any] | str
    ) -> VerifiedRegistration:
        record = self.challenges.pop(key=flow_id, kind="registration")
        if record.user is None:
            raise ChallengeNotFound("registration challenge has no user")
        if isinstance(credential, Mapping):
            credential_data = dict(credential)
        else:
            credential_data = json.loads(credential)
            if not isinstance(credential_data, dict):
                raise ValueError("credential JSON must be an object")
        verified = verify_registration_response(
            credential=credential_data,
            expected_challenge=record.challenge,
            expected_rp_id=self.config.rp_id,
            expected_origin=self.config.origin,
            require_user_verification=self.config.require_user_verification,
        )
        passkey = PasskeyCredential(
            verified.credential_id,
            record.user.user_id,
            verified.credential_public_key,
            verified.sign_count,
            _transports_from_response(credential_data),
            _enum_value(getattr(verified, "credential_device_type", None)),
            getattr(verified, "credential_backed_up", None),
        )
        return VerifiedRegistration(record.user, passkey)

    def begin_authentication(
        self,
        *,
        flow_id: str,
        allow_credentials: Iterable[PasskeyCredential] | None = None,
    ) -> dict[str, Any]:
        descriptors = [
            PublicKeyCredentialDescriptor(
                id=c.credential_id,
                transports=[AuthenticatorTransport(t) for t in c.transports] or None,
            )
            for c in allow_credentials or []
        ]
        options = generate_authentication_options(
            rp_id=self.config.rp_id,
            timeout=self.config.timeout_ms,
            allow_credentials=descriptors,
            user_verification=self.config.user_verification_requirement,
        )
        self.challenges.save(
            key=flow_id,
            kind="authentication",
            challenge=options.challenge,
            ttl_seconds=self.config.challenge_ttl_seconds,
        )
        return _json_options(options)

    def finish_authentication(
        self,
        *,
        flow_id: str,
        credential: Mapping[str, Any] | str,
        require_user_handle: bool = True,
    ) -> AuthenticationResult:
        if isinstance(credential, Mapping):
            credential_data = dict(credential)
        else:
            credential_data = json.loads(credential)
            if not isinstance(credential_data, dict):
                raise ValueError("credential JSON must be an object")
        credential_id = _credential_id_from_response(credential_data)
        stored = self.credentials.get_credential(credential_id)
        if stored is None:
            raise CredentialNotFound("unknown passkey credential")
        user = self.credentials.get_user(stored.user_id)
        if user is None:
            raise CredentialNotFound("credential has no user")
        user_handle = _user_handle_from_response(credential_data)
        if user_handle != user.user_handle and (
            require_user_handle or user_handle is not None
        ):
            raise UserHandleMismatch("credential userHandle does not match stored user")
        record = self.challenges.pop(key=flow_id, kind="authentication")
        verified = verify_authentication_response(
            credential=credential_data,
            expected_challenge=record.challenge,
            expected_rp_id=self.config.rp_id,
            expected_origin=self.config.origin,
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count,
            require_user_verification=self.config.require_user_verification,
        )
        updated = self.credentials.compare_and_set_credential_after_login(
            credential_id,
            expected_sign_count=stored.sign_count,
            new_sign_count=verified.new_sign_count,
            device_type=_enum_value(getattr(verified, "credential_device_type", None)),
            backed_up=getattr(verified, "credential_backed_up", None),
        )
        return AuthenticationResult(user, updated)
