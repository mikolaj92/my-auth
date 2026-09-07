from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any

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
)

from .passkey_errors import (
    ChallengeNotFound,
    CredentialCounterConflict,
    CredentialMutationDenied,
    CredentialNotFound,
    PasskeyCredentialConflict,
    PasskeyUserConflict,
    UserHandleMismatch,
)
from .passkey_memory import MemoryChallengeStore, MemoryCredentialStore
from .passkey_models import (
    PASSKEY_SQLITE_CHALLENGE_SCHEMA,
    PASSKEY_SQLITE_SCHEMA,
    AuthenticationResult,
    ChallengeKind,
    ChallengeRecord,
    ChallengeStore,
    CredentialStore,
    PasskeyConfig,
    PasskeyCredential,
    PasskeyUser,
    RegistrationContext,
    RegistrationKind,
    VerifiedRegistration,
    b64url_to_bytes,
    bytes_to_b64url,
    registration_context_from_capability,
)
from .passkey_sqlite import SQLiteChallengeStore, SQLiteCredentialStore

__all__ = [
    "PASSKEY_SQLITE_CHALLENGE_SCHEMA",
    "PASSKEY_SQLITE_SCHEMA",
    "AuthenticationResult",
    "ChallengeKind",
    "ChallengeNotFound",
    "ChallengeRecord",
    "ChallengeStore",
    "CredentialCounterConflict",
    "CredentialMutationDenied",
    "CredentialNotFound",
    "CredentialStore",
    "MemoryChallengeStore",
    "MemoryCredentialStore",
    "PasskeyConfig",
    "PasskeyCredential",
    "PasskeyCredentialConflict",
    "PasskeyService",
    "PasskeyUser",
    "PasskeyUserConflict",
    "RegistrationContext",
    "RegistrationKind",
    "SQLiteChallengeStore",
    "SQLiteCredentialStore",
    "UserHandleMismatch",
    "VerifiedRegistration",
    "b64url_to_bytes",
    "bytes_to_b64url",
    "normalize_credential_label",
    "registration_context_from_capability",
]


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


def normalize_credential_label(label: str | None) -> str | None:
    if label is None:
        return None
    normalized = label.strip()
    if len(normalized) > 80:
        raise ValueError("credential label must be at most 80 characters")
    return normalized or None


class PasskeyService:
    def __init__(
        self,
        *,
        config: PasskeyConfig,
        challenges: ChallengeStore,
        credentials: CredentialStore,
    ) -> None:
        self.config, self.challenges, self.credentials = config, challenges, credentials

    def list_credentials(self, *, user_id: str) -> list[PasskeyCredential]:
        return list(self.credentials.list_credentials_for_user(user_id))

    def label_credential(
        self, *, user_id: str, credential_id: bytes, label: str | None
    ) -> PasskeyCredential:
        credential = self.credentials.update_credential_label(
            credential_id,
            user_id=user_id,
            label=normalize_credential_label(label),
        )
        if credential is None:
            raise CredentialNotFound("unknown passkey credential")
        return credential

    def remove_credential(
        self,
        *,
        user_id: str,
        credential_id: bytes,
        allow_final: bool = False,
    ) -> None:
        if self.credentials.delete_credential(
            credential_id,
            user_id=user_id,
            require_remaining=not allow_final,
        ):
            return
        credential = self.credentials.get_credential(credential_id)
        if credential is None or credential.user_id != user_id:
            raise CredentialNotFound("unknown passkey credential")
        raise CredentialMutationDenied("final passkey credential cannot be removed")

    def begin_registration(
        self,
        *,
        flow_id: str,
        user: PasskeyUser | None = None,
        context: RegistrationContext | None = None,
    ) -> dict[str, Any]:
        if context is None:
            if user is None:
                raise ValueError("registration user or context is required")
            context = RegistrationContext(kind="self_registration", user=user)
        elif user is not None and user != context.user:
            raise ValueError("registration user does not match context")
        user = context.user
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
            registration_context=context,
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
                raise ValueError(  # noqa: TRY004 - preserve public exception contract
                    "credential JSON must be an object"
                )
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
        return VerifiedRegistration(record.user, passkey, record.registration_context)

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
                raise ValueError(  # noqa: TRY004 - preserve public exception contract
                    "credential JSON must be an object"
                )
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
