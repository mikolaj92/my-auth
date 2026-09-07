from __future__ import annotations

from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal, Protocol
from urllib.parse import urlparse

from webauthn.helpers.structs import UserVerificationRequirement

ChallengeKind = Literal["registration", "authentication"]
RegistrationKind = Literal[
    "self_registration",
    "invitation",
    "additional_credential",
    "recovery",
]


def bytes_to_b64url(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_to_bytes(value: str) -> bytes:
    return urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))


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
        _ = parsed.port
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
class RegistrationContext:
    kind: RegistrationKind
    user: PasskeyUser
    capability_id: str | None = None

    def __post_init__(self) -> None:
        if self.kind in {"invitation", "recovery"} and not self.capability_id:
            raise ValueError(f"{self.kind} registration requires a capability")
        if (
            self.kind
            in {
                "self_registration",
                "additional_credential",
            }
            and self.capability_id
        ):
            raise ValueError(f"{self.kind} registration cannot use a capability")


def registration_context_from_capability(
    *,
    kind: Literal["invitation", "recovery"],
    user: PasskeyUser,
    capability_id: str,
    capability_subject: str,
    capability_purpose: Literal["invitation", "account_recovery"],
) -> RegistrationContext:
    expected_purpose = "invitation" if kind == "invitation" else "account_recovery"
    if capability_subject != user.user_id or capability_purpose != expected_purpose:
        raise ValueError("capability does not match registration subject or purpose")
    return RegistrationContext(
        kind=kind,
        user=user,
        capability_id=capability_id,
    )


@dataclass(frozen=True)
class ChallengeRecord:
    challenge: bytes
    kind: ChallengeKind
    key: str
    expires_at: datetime
    user: PasskeyUser | None = None
    registration_kind: RegistrationKind | None = None
    capability_id: str | None = None

    @property
    def registration_context(self) -> RegistrationContext | None:
        if self.user is None or self.registration_kind is None:
            return None
        return RegistrationContext(
            kind=self.registration_kind,
            user=self.user,
            capability_id=self.capability_id,
        )


@dataclass(frozen=True)
class AuthenticationResult:
    user: PasskeyUser
    credential: PasskeyCredential


@dataclass(frozen=True)
class VerifiedRegistration:
    user: PasskeyUser
    credential: PasskeyCredential
    context: RegistrationContext | None = None


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
    def update_credential_label(
        self, credential_id: bytes, *, user_id: str, label: str | None
    ) -> PasskeyCredential | None: ...
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
        registration_context: RegistrationContext | None = None,
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
 user_id TEXT, user_handle TEXT, user_name TEXT, user_display_name TEXT,
 registration_kind TEXT, capability_id TEXT, PRIMARY KEY (key, kind)
);
CREATE INDEX IF NOT EXISTS idx_passkey_challenges_expires_at ON passkey_challenges(expires_at);
"""


