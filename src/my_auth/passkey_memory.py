from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta

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
)


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
            self._now() + timedelta(seconds=ttl_seconds),
            user,
            registration_context.kind if registration_context else None,
            registration_context.capability_id if registration_context else None,
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

    def update_credential_label(
        self, credential_id: bytes, *, user_id: str, label: str | None
    ) -> PasskeyCredential | None:
        with self._lock:
            credential = self.credentials.get(credential_id)
            if credential is None or credential.user_id != user_id:
                return None
            credential.label = label
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
