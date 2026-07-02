from __future__ import annotations

import json
import sqlite3
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Iterable, Mapping
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


class ChallengeNotFound(Exception):
    pass


class CredentialNotFound(Exception):
    pass


class UserHandleMismatch(Exception):
    pass


def bytes_to_b64url(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_to_bytes(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return urlsafe_b64decode((value + padding).encode("ascii"))


def _enum_value(value: Any) -> str | None:
    if value is None:
        return None
    return getattr(value, "value", str(value))


def _json_options(options: Any) -> dict[str, Any]:
    return json.loads(options_to_json(options))


def _credential_id_from_response(credential: Mapping[str, Any]) -> bytes:
    raw_id = credential.get("rawId") or credential.get("id")
    if isinstance(raw_id, bytes):
        return raw_id
    if isinstance(raw_id, str):
        return b64url_to_bytes(raw_id)
    raise CredentialNotFound("credential response has no id/rawId")


def _user_handle_from_response(credential: Mapping[str, Any]) -> bytes | None:
    response = credential.get("response")
    if not isinstance(response, Mapping):
        return None
    user_handle = response.get("userHandle")
    if isinstance(user_handle, bytes):
        return user_handle
    if isinstance(user_handle, str) and user_handle:
        return b64url_to_bytes(user_handle)
    return None


def _transports_from_response(credential: Mapping[str, Any]) -> list[str]:
    response = credential.get("response")
    if not isinstance(response, Mapping):
        return []
    transports = response.get("transports") or []
    return [str(getattr(transport, "value", transport)) for transport in transports]


def _origin_allowed(origin: str) -> bool:
    parsed = urlparse(origin)
    if not parsed.scheme or not parsed.netloc or parsed.path or parsed.params or parsed.query or parsed.fragment:
        return False
    if parsed.username or parsed.password:
        return False
    try:
        hostname = parsed.hostname
        parsed.port
    except ValueError:
        return False
    if parsed.scheme == "https":
        return hostname is not None
    return parsed.scheme == "http" and hostname in {"localhost", "127.0.0.1", "::1"}


@dataclass(frozen=True)
class PasskeyConfig:
    rp_id: str
    rp_name: str
    origin: str
    timeout_ms: int = 60_000
    challenge_ttl_seconds: int = 300
    user_verification: Literal["required", "preferred", "discouraged"] = "required"

    def __post_init__(self) -> None:
        if "://" in self.rp_id or "/" in self.rp_id or ":" in self.rp_id:
            raise ValueError("rp_id must be a hostname only, without scheme, port, or path")
        if not _origin_allowed(self.origin):
            raise ValueError("origin must be https:// in production; http is only allowed for localhost")

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


class CredentialStore(Protocol):
    def save_user(self, user: PasskeyUser) -> None: ...

    def get_user(self, user_id: str) -> PasskeyUser | None: ...

    def get_user_by_handle(self, user_handle: bytes) -> PasskeyUser | None: ...

    def list_credentials_for_user(self, user_id: str) -> Iterable[PasskeyCredential]: ...

    def get_credential(self, credential_id: bytes) -> PasskeyCredential | None: ...

    def save_credential(self, credential: PasskeyCredential) -> None: ...

    def update_credential_after_login(
        self,
        credential_id: bytes,
        *,
        sign_count: int,
        device_type: str | None,
        backed_up: bool | None,
    ) -> PasskeyCredential: ...

    def delete_credential(self, credential_id: bytes, *, user_id: str | None = None) -> bool: ...


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
  user_id TEXT PRIMARY KEY,
  user_handle TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  display_name TEXT
);

CREATE TABLE IF NOT EXISTS passkey_credentials (
  credential_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES passkey_users(user_id) ON DELETE CASCADE,
  public_key BLOB NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  device_type TEXT,
  backed_up INTEGER,
  label TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_passkey_credentials_user_id
  ON passkey_credentials(user_id);
"""


PASSKEY_SQLITE_CHALLENGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS passkey_challenges (
  key TEXT NOT NULL,
  kind TEXT NOT NULL,
  challenge BLOB NOT NULL,
  expires_at TEXT NOT NULL,
  user_id TEXT,
  user_handle TEXT,
  user_name TEXT,
  user_display_name TEXT,
  PRIMARY KEY (key, kind)
);

CREATE INDEX IF NOT EXISTS idx_passkey_challenges_expires_at
  ON passkey_challenges(expires_at);
"""


_CREDENTIAL_COLUMNS = (
    "credential_id, user_id, public_key, sign_count, transports, device_type, backed_up, label, created_at"
)

_CHALLENGE_COLUMNS = "challenge, kind, key, expires_at, user_id, user_handle, user_name, user_display_name"


class MemoryChallengeStore:
    def __init__(self, *, now: Any | None = None) -> None:
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
            challenge=challenge,
            kind=kind,
            key=key,
            expires_at=self._now() + timedelta(seconds=ttl_seconds),
            user=user,
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
        expired = [key for key, record in self._records.items() if record.expires_at <= now]
        for key in expired:
            del self._records[key]
        return len(expired)


class SQLiteChallengeStore:
    def __init__(
        self,
        database: str | Path | sqlite3.Connection,
        *,
        create_schema: bool = True,
        now: Any | None = None,
    ) -> None:
        self.connection = (
            database if isinstance(database, sqlite3.Connection) else sqlite3.connect(database, check_same_thread=False)
        )
        self._now = now or (lambda: datetime.now(UTC))
        if create_schema:
            self.create_schema()

    def create_schema(self) -> None:
        self.connection.executescript(PASSKEY_SQLITE_CHALLENGE_SCHEMA)

    def close(self) -> None:
        self.connection.close()

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
            challenge=challenge,
            kind=kind,
            key=key,
            expires_at=_utc(self._now() + timedelta(seconds=ttl_seconds)),
            user=user,
        )
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO passkey_challenges (
                  key, kind, challenge, expires_at, user_id, user_handle, user_name, user_display_name
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(key, kind) DO UPDATE SET
                  challenge = excluded.challenge,
                  expires_at = excluded.expires_at,
                  user_id = excluded.user_id,
                  user_handle = excluded.user_handle,
                  user_name = excluded.user_name,
                  user_display_name = excluded.user_display_name
                """,
                _sqlite_challenge_values(record),
            )
        return record

    def pop(self, *, key: str, kind: ChallengeKind) -> ChallengeRecord:
        with self.connection:
            row = self.connection.execute(
                f"""
                DELETE FROM passkey_challenges
                WHERE key = ? AND kind = ? AND expires_at > ?
                RETURNING {_CHALLENGE_COLUMNS}
                """,
                (key, kind, _sqlite_datetime(self._now())),
            ).fetchone()
        if row is None:
            self.cleanup_expired()
            raise ChallengeNotFound(f"missing or expired {kind} challenge")
        return _sqlite_challenge(row)

    def cleanup_expired(self) -> int:
        with self.connection:
            cursor = self.connection.execute(
                "DELETE FROM passkey_challenges WHERE expires_at <= ?",
                (_sqlite_datetime(self._now()),),
            )
        return cursor.rowcount


class MemoryCredentialStore:
    def __init__(self) -> None:
        self.users: dict[str, PasskeyUser] = {}
        self.users_by_handle: dict[bytes, str] = {}
        self.credentials: dict[bytes, PasskeyCredential] = {}

    def save_user(self, user: PasskeyUser) -> None:
        self.users[user.user_id] = user
        self.users_by_handle[user.user_handle] = user.user_id

    def get_user(self, user_id: str) -> PasskeyUser | None:
        return self.users.get(user_id)

    def get_user_by_handle(self, user_handle: bytes) -> PasskeyUser | None:
        user_id = self.users_by_handle.get(user_handle)
        return self.users.get(user_id) if user_id else None

    def list_credentials_for_user(self, user_id: str) -> Iterable[PasskeyCredential]:
        return [credential for credential in self.credentials.values() if credential.user_id == user_id]

    def get_credential(self, credential_id: bytes) -> PasskeyCredential | None:
        return self.credentials.get(credential_id)

    def save_credential(self, credential: PasskeyCredential) -> None:
        self.credentials[credential.credential_id] = credential

    def update_credential_after_login(
        self,
        credential_id: bytes,
        *,
        sign_count: int,
        device_type: str | None,
        backed_up: bool | None,
    ) -> PasskeyCredential:
        credential = self.credentials[credential_id]
        credential.sign_count = sign_count
        credential.device_type = device_type
        credential.backed_up = backed_up
        return credential

    def delete_credential(self, credential_id: bytes, *, user_id: str | None = None) -> bool:
        credential = self.credentials.get(credential_id)
        if credential is None or (user_id is not None and credential.user_id != user_id):
            return False
        del self.credentials[credential_id]
        return True


class SQLiteCredentialStore:
    def __init__(
        self,
        database: str | Path | sqlite3.Connection,
        *,
        create_schema: bool = True,
    ) -> None:
        self.connection = (
            database if isinstance(database, sqlite3.Connection) else sqlite3.connect(database, check_same_thread=False)
        )
        self.connection.execute("PRAGMA foreign_keys = ON")
        if create_schema:
            self.create_schema()

    def create_schema(self) -> None:
        self.connection.executescript(PASSKEY_SQLITE_SCHEMA)

    def close(self) -> None:
        self.connection.close()

    def save_user(self, user: PasskeyUser) -> None:
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO passkey_users (user_id, user_handle, name, display_name)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                  user_handle = excluded.user_handle,
                  name = excluded.name,
                  display_name = excluded.display_name
                """,
                (user.user_id, bytes_to_b64url(user.user_handle), user.name, user.display_name),
            )

    def get_user(self, user_id: str) -> PasskeyUser | None:
        row = self.connection.execute(
            "SELECT user_id, user_handle, name, display_name FROM passkey_users WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        return _sqlite_user(row)

    def get_user_by_handle(self, user_handle: bytes) -> PasskeyUser | None:
        row = self.connection.execute(
            "SELECT user_id, user_handle, name, display_name FROM passkey_users WHERE user_handle = ?",
            (bytes_to_b64url(user_handle),),
        ).fetchone()
        return _sqlite_user(row)

    def list_credentials_for_user(self, user_id: str) -> Iterable[PasskeyCredential]:
        rows = self.connection.execute(
            f"""
            SELECT {_CREDENTIAL_COLUMNS}
            FROM passkey_credentials
            WHERE user_id = ?
            ORDER BY created_at, credential_id
            """,
            (user_id,),
        ).fetchall()
        return [_sqlite_credential(row) for row in rows]

    def get_credential(self, credential_id: bytes) -> PasskeyCredential | None:
        row = self.connection.execute(
            f"SELECT {_CREDENTIAL_COLUMNS} FROM passkey_credentials WHERE credential_id = ?",
            (bytes_to_b64url(credential_id),),
        ).fetchone()
        return _sqlite_credential(row) if row else None

    def save_credential(self, credential: PasskeyCredential) -> None:
        with self.connection:
            self.connection.execute(
                f"""
                INSERT INTO passkey_credentials ({_CREDENTIAL_COLUMNS})
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                _sqlite_credential_values(credential),
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
            self.connection.execute(
                """
                UPDATE passkey_credentials
                SET sign_count = ?, device_type = ?, backed_up = ?
                WHERE credential_id = ?
                """,
                (sign_count, device_type, _sqlite_bool(backed_up), bytes_to_b64url(credential_id)),
            )
        credential = self.get_credential(credential_id)
        if credential is None:
            raise CredentialNotFound("unknown passkey credential")
        return credential

    def delete_credential(self, credential_id: bytes, *, user_id: str | None = None) -> bool:
        sql = "DELETE FROM passkey_credentials WHERE credential_id = ?"
        params: tuple[str, ...] = (bytes_to_b64url(credential_id),)
        if user_id is not None:
            sql += " AND user_id = ?"
            params = (*params, user_id)
        with self.connection:
            cursor = self.connection.execute(sql, params)
        return cursor.rowcount > 0


def _sqlite_user(row: Any) -> PasskeyUser | None:
    if row is None:
        return None
    return PasskeyUser(
        user_id=row[0],
        user_handle=b64url_to_bytes(row[1]),
        name=row[2],
        display_name=row[3],
    )


def _sqlite_credential(row: Any) -> PasskeyCredential:
    transports = json.loads(row[4]) if row[4] else []
    return PasskeyCredential(
        credential_id=b64url_to_bytes(row[0]),
        user_id=row[1],
        public_key=row[2],
        sign_count=row[3],
        transports=[str(transport) for transport in transports],
        device_type=row[5],
        backed_up=None if row[6] is None else bool(row[6]),
        label=row[7],
        created_at=datetime.fromisoformat(row[8]),
    )


def _sqlite_credential_values(credential: PasskeyCredential) -> tuple[Any, ...]:
    return (
        bytes_to_b64url(credential.credential_id),
        credential.user_id,
        credential.public_key,
        credential.sign_count,
        json.dumps(credential.transports) if credential.transports else None,
        credential.device_type,
        _sqlite_bool(credential.backed_up),
        credential.label,
        credential.created_at.isoformat(),
    )


def _sqlite_bool(value: bool | None) -> int | None:
    if value is None:
        return None
    return int(value)


def _sqlite_challenge(row: Any) -> ChallengeRecord:
    user = None
    if row[4] is not None:
        user = PasskeyUser(
            user_id=row[4],
            user_handle=b64url_to_bytes(row[5]),
            name=row[6],
            display_name=row[7],
        )
    return ChallengeRecord(
        challenge=row[0],
        kind=row[1],
        key=row[2],
        expires_at=datetime.fromisoformat(row[3]),
        user=user,
    )


def _sqlite_challenge_values(record: ChallengeRecord) -> tuple[Any, ...]:
    user = record.user
    return (
        record.key,
        record.kind,
        record.challenge,
        _sqlite_datetime(record.expires_at),
        user.user_id if user else None,
        bytes_to_b64url(user.user_handle) if user else None,
        user.name if user else None,
        user.display_name if user else None,
    )


def _sqlite_datetime(value: datetime) -> str:
    return _utc(value).isoformat()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class PasskeyService:
    def __init__(
        self,
        *,
        config: PasskeyConfig,
        challenges: ChallengeStore,
        credentials: CredentialStore,
    ) -> None:
        self.config = config
        self.challenges = challenges
        self.credentials = credentials

    def begin_registration(self, *, flow_id: str, user: PasskeyUser) -> dict[str, Any]:
        existing = [
            PublicKeyCredentialDescriptor(id=credential.credential_id)
            for credential in self.credentials.list_credentials_for_user(user.user_id)
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

    def finish_registration(self, *, flow_id: str, credential: Mapping[str, Any] | str) -> PasskeyCredential:
        record = self.challenges.pop(key=flow_id, kind="registration")
        if record.user is None:
            raise ChallengeNotFound("registration challenge has no user")

        verified = verify_registration_response(
            credential=credential,
            expected_challenge=record.challenge,
            expected_rp_id=self.config.rp_id,
            expected_origin=self.config.origin,
            require_user_verification=self.config.require_user_verification,
        )
        passkey = PasskeyCredential(
            credential_id=verified.credential_id,
            user_id=record.user.user_id,
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
            transports=_transports_from_response(credential) if isinstance(credential, Mapping) else [],
            device_type=_enum_value(getattr(verified, "credential_device_type", None)),
            backed_up=getattr(verified, "credential_backed_up", None),
        )
        self.credentials.save_user(record.user)
        self.credentials.save_credential(passkey)
        return passkey

    def begin_authentication(
        self,
        *,
        flow_id: str,
        allow_credentials: Iterable[PasskeyCredential] | None = None,
    ) -> dict[str, Any]:
        descriptors = [
            PublicKeyCredentialDescriptor(
                id=credential.credential_id,
                transports=[AuthenticatorTransport(t) for t in credential.transports] or None,
            )
            for credential in allow_credentials or []
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
        if not isinstance(credential, Mapping):
            credential = json.loads(credential)
        credential_id = _credential_id_from_response(credential)
        stored = self.credentials.get_credential(credential_id)
        if stored is None:
            raise CredentialNotFound("unknown passkey credential")
        user = self.credentials.get_user(stored.user_id)
        if user is None:
            raise CredentialNotFound("credential has no user")

        user_handle = _user_handle_from_response(credential)
        if user_handle != user.user_handle and (require_user_handle or user_handle is not None):
            raise UserHandleMismatch("credential userHandle does not match stored user")

        record = self.challenges.pop(key=flow_id, kind="authentication")
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=record.challenge,
            expected_rp_id=self.config.rp_id,
            expected_origin=self.config.origin,
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count,
            require_user_verification=self.config.require_user_verification,
        )
        updated = self.credentials.update_credential_after_login(
            credential_id,
            sign_count=verified.new_sign_count,
            device_type=_enum_value(getattr(verified, "credential_device_type", None)),
            backed_up=getattr(verified, "credential_backed_up", None),
        )
        return AuthenticationResult(user=user, credential=updated)
