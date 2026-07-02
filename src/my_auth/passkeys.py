from __future__ import annotations

import json
import sqlite3
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Iterable, Mapping
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


class SQLiteChallengeStore:
    """Shared challenge store safe for multi-process/multi-worker deployments.

    Challenges are consumed atomically (single ``DELETE ... RETURNING``), so a
    challenge can never be verified twice, even across workers.
    """

    def __init__(self, path: str | Path, *, now: Any | None = None) -> None:
        self._path = str(path)
        self._now = now or (lambda: datetime.now(UTC))
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS passkey_challenges (
                    key TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    challenge BLOB NOT NULL,
                    expires_at REAL NOT NULL,
                    user_json TEXT,
                    PRIMARY KEY (key, kind)
                )
                """
            )

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self._path, timeout=5.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            with conn:
                yield conn
        finally:
            conn.close()

    def save(
        self,
        *,
        key: str,
        kind: ChallengeKind,
        challenge: bytes,
        ttl_seconds: int,
        user: PasskeyUser | None = None,
    ) -> ChallengeRecord:
        expires_at = self._now() + timedelta(seconds=ttl_seconds)
        user_json = None
        if user is not None:
            user_json = json.dumps(
                {
                    "user_id": user.user_id,
                    "user_handle": bytes_to_b64url(user.user_handle),
                    "name": user.name,
                    "display_name": user.display_name,
                }
            )
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO passkey_challenges (key, kind, challenge, expires_at, user_json)"
                " VALUES (?, ?, ?, ?, ?)",
                (key, kind, challenge, expires_at.timestamp(), user_json),
            )
        return ChallengeRecord(challenge=challenge, kind=kind, key=key, expires_at=expires_at, user=user)

    def pop(self, *, key: str, kind: ChallengeKind) -> ChallengeRecord:
        with self._connect() as conn:
            row = conn.execute(
                "DELETE FROM passkey_challenges WHERE key = ? AND kind = ?"
                " RETURNING challenge, expires_at, user_json",
                (key, kind),
            ).fetchone()
        if row is None:
            raise ChallengeNotFound(f"missing or expired {kind} challenge")
        challenge, expires_at_ts, user_json = row
        expires_at = datetime.fromtimestamp(expires_at_ts, tz=UTC)
        if expires_at <= self._now():
            raise ChallengeNotFound(f"missing or expired {kind} challenge")
        user = None
        if user_json is not None:
            data = json.loads(user_json)
            user = PasskeyUser(
                user_id=data["user_id"],
                user_handle=b64url_to_bytes(data["user_handle"]),
                name=data["name"],
                display_name=data["display_name"],
            )
        return ChallengeRecord(
            challenge=bytes(challenge),
            kind=kind,
            key=key,
            expires_at=expires_at,
            user=user,
        )

    def cleanup_expired(self) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM passkey_challenges WHERE expires_at <= ?",
                (self._now().timestamp(),),
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
