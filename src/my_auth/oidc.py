"""Framework-neutral contracts for the optional my-auth OpenID Provider.

The passkey package remains usable without Authlib or a JOSE implementation.
This module contains only standard-library values, stores, and host mapping
contracts. The FastAPI/Authlib protocol adapter lives in
:mod:`my_auth.oidc_fastapi` and is imported explicitly by applications that opt
in to the provider.
"""

from __future__ import annotations

import base64
import re
import secrets
import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from hashlib import sha256
from hmac import compare_digest
from time import time
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit

OIDC_SCOPE = Literal["openid", "profile", "email"]
_SUPPORTED_SCOPES: frozenset[str] = frozenset({"openid", "profile", "email"})
_CODE_VERIFIER_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
_HEX_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class OIDCConfigurationError(ValueError):
    """Raised when provider or client configuration is unsafe or incomplete."""


class OIDCProtocolError(ValueError):
    """Raised for malformed values at the framework-neutral provider seam."""


def _absolute_https_url(
    value: str,
    *,
    field_name: str,
    allow_query: bool = False,
) -> None:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise OIDCConfigurationError(f"{field_name} must be a non-empty URL")
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or (parts.query and not allow_query)
        or parts.fragment
    ):
        suffix = (
            " without query or fragment" if not allow_query else " without fragment"
        )
        raise OIDCConfigurationError(
            f"{field_name} must be an absolute HTTPS URL{suffix}"
        )
    try:
        _ = parts.port
    except ValueError as error:
        raise OIDCConfigurationError(f"{field_name} has an invalid port") from error


def _origin(value: str) -> tuple[str, str, int]:
    parts = urlsplit(value)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.scheme, (parts.hostname or "").casefold(), port


def _scope_string(scope: str | Iterable[str] | None) -> str:
    if scope is None:
        return ""
    if isinstance(scope, str):
        return scope.strip()
    return " ".join(str(item) for item in scope)


def _scope_tuple(scope: str | Iterable[str] | None) -> tuple[str, ...]:
    value = _scope_string(scope)
    if not value:
        return ()
    values = tuple(value.split())
    if len(set(values)) != len(values):
        raise OIDCProtocolError("scope must not contain duplicate values")
    return values


def _validate_code_challenge(code_challenge: str) -> str:
    if not isinstance(code_challenge, str) or not _CODE_VERIFIER_PATTERN.fullmatch(
        code_challenge
    ):
        raise OIDCProtocolError(
            "code_challenge must be a base64url value of 43-128 characters"
        )
    return code_challenge


def _validate_code_verifier(code_verifier: str) -> str:
    if not isinstance(code_verifier, str) or not _CODE_VERIFIER_PATTERN.fullmatch(
        code_verifier
    ):
        raise OIDCProtocolError("code_verifier must be 43-128 RFC 7636 characters")
    return code_verifier


def create_s256_code_challenge(code_verifier: str) -> str:
    """Return the RFC 7636 ``S256`` challenge for an ASCII verifier."""
    verifier = _validate_code_verifier(code_verifier)
    digest = sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@dataclass(frozen=True, slots=True)
class OIDCProviderConfig:
    """Issuer and endpoint metadata for the supported OIDC profile."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None = None
    revocation_endpoint: str | None = None

    def __post_init__(self) -> None:
        _absolute_https_url(self.issuer, field_name="issuer")
        issuer_origin = _origin(self.issuer)
        for name in (
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "userinfo_endpoint",
            "revocation_endpoint",
        ):
            value = getattr(self, name)
            if value is None:
                continue
            _absolute_https_url(value, field_name=name)
            if _origin(value) != issuer_origin:
                raise OIDCConfigurationError(f"{name} must use the issuer origin")

    @property
    def discovery_endpoint(self) -> str:
        """Return the discovery URL for this issuer identifier."""
        return self.issuer.rstrip("/") + "/.well-known/openid-configuration"

    def metadata(self) -> dict[str, object]:
        """Return a fresh OpenID Discovery metadata mapping."""
        result: dict[str, object] = {
            "issuer": self.issuer,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "jwks_uri": self.jwks_uri,
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "email"],
            "token_endpoint_auth_methods_supported": [
                "none",
                "client_secret_basic",
            ],
            "code_challenge_methods_supported": ["S256"],
        }
        if self.userinfo_endpoint is not None:
            result["userinfo_endpoint"] = self.userinfo_endpoint
        if self.revocation_endpoint is not None:
            result["revocation_endpoint"] = self.revocation_endpoint
        return result


@dataclass(frozen=True, slots=True)
class OIDCClient:
    """Immutable registered client implementing Authlib's client contract."""

    client_id: str
    redirect_uris: tuple[str, ...]
    scopes: tuple[str, ...] = ("openid",)
    client_secret_hash: str | None = None
    token_endpoint_auth_method: Literal["none", "client_secret_basic"] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.client_id, str) or not self.client_id:
            raise OIDCConfigurationError("client_id is required")
        if any(character.isspace() for character in self.client_id):
            raise OIDCConfigurationError("client_id must not contain whitespace")
        if not self.redirect_uris:
            raise OIDCConfigurationError("at least one redirect URI is required")
        if "openid" not in self.scopes:
            raise OIDCConfigurationError("OIDC client must allow openid scope")
        if len(set(self.scopes)) != len(self.scopes):
            raise OIDCConfigurationError("client scopes must not contain duplicates")
        unknown_scopes = set(self.scopes) - _SUPPORTED_SCOPES
        if unknown_scopes:
            raise OIDCConfigurationError(
                "unsupported client scopes: " + ", ".join(sorted(unknown_scopes))
            )
        for uri in self.redirect_uris:
            _absolute_https_url(uri, field_name="redirect URI", allow_query=True)
        if self.client_secret_hash is not None and not _HEX_SHA256_PATTERN.fullmatch(
            self.client_secret_hash
        ):
            raise OIDCConfigurationError(
                "client_secret_hash must be a lowercase SHA-256 hex digest"
            )
        method = self.token_endpoint_auth_method
        if method is None:
            method = "client_secret_basic" if self.client_secret_hash else "none"
            object.__setattr__(self, "token_endpoint_auth_method", method)
        if method not in {"none", "client_secret_basic"}:
            raise OIDCConfigurationError("unsupported token endpoint auth method")
        if method == "none" and self.client_secret_hash is not None:
            raise OIDCConfigurationError(
                "public clients must not have a client secret hash"
            )
        if method == "client_secret_basic" and self.client_secret_hash is None:
            raise OIDCConfigurationError(
                "client_secret_basic clients require a client secret hash"
            )

    @property
    def client_metadata(self) -> Mapping[str, object]:
        """Return Authlib-compatible client metadata without mutable state."""
        return {
            "client_id": self.client_id,
            "redirect_uris": list(self.redirect_uris),
            "scope": " ".join(self.scopes),
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": self.token_endpoint_auth_method,
            "id_token_signed_response_alg": "RS256",
        }

    @property
    def id_token_signed_response_alg(self) -> Literal["RS256"]:
        return "RS256"

    def get_client_id(self) -> str:
        return self.client_id

    def get_default_redirect_uri(self) -> str:
        return self.redirect_uris[0]

    def get_allowed_scope(self, scope: str | None) -> str | None:
        requested = _scope_tuple(scope)
        if not requested:
            return " ".join(self.scopes)
        if not set(requested).issubset(self.scopes):
            return None
        return " ".join(requested)

    def check_redirect_uri(self, redirect_uri: str) -> bool:
        return validate_client_redirect(self, redirect_uri)

    def check_client_secret(self, client_secret: str) -> bool:
        if self.client_secret_hash is None or not isinstance(client_secret, str):
            return False
        candidate = sha256(client_secret.encode("utf-8")).hexdigest()
        return compare_digest(candidate, self.client_secret_hash)

    def check_endpoint_auth_method(self, method: str, endpoint: str) -> bool:
        if endpoint != "token":
            return True
        return method == self.token_endpoint_auth_method

    def check_response_type(self, response_type: str) -> bool:
        return response_type == "code"

    def check_grant_type(self, grant_type: str) -> bool:
        return grant_type == "authorization_code"


def hash_client_secret(client_secret: str) -> str:
    """Hash a client secret for ``OIDCClient.client_secret_hash`` storage."""
    if not isinstance(client_secret, str) or not client_secret:
        raise ValueError("client_secret must be a non-empty string")
    return sha256(client_secret.encode("utf-8")).hexdigest()


def validate_client_redirect(client: OIDCClient, redirect_uri: str) -> bool:
    """Validate an exact registered redirect URI; never normalize or wildcard-match."""
    return redirect_uri in client.redirect_uris


@dataclass(slots=True)
class AuthorizationCode:
    """Short-lived, one-time code bound to client, redirect, user and PKCE."""

    value: str
    client_id: str
    redirect_uri: str
    subject: str
    scope: tuple[str, ...]
    nonce: str
    code_challenge: str
    expires_at: int
    code_challenge_method: Literal["S256"] = "S256"
    auth_time: int | None = None
    acr: str | None = None
    amr: tuple[str, ...] = ()
    user: object | None = field(default=None, repr=False, compare=False)
    redeemed: bool = False

    @classmethod
    def issue(
        cls,
        *,
        client_id: str,
        redirect_uri: str,
        subject: str,
        scope: tuple[str, ...],
        nonce: str,
        code_challenge: str,
        now: int,
        code_challenge_method: Literal["S256"] = "S256",
        lifetime_seconds: int = 300,
        auth_time: int | None = None,
        acr: str | None = None,
        amr: tuple[str, ...] = (),
        user: object | None = None,
        value: str | None = None,
    ) -> AuthorizationCode:
        if "openid" not in scope or not nonce:
            raise OIDCProtocolError("authorization code requires openid and nonce")
        if code_challenge_method != "S256":
            raise OIDCProtocolError("only S256 PKCE is supported")
        _validate_code_challenge(code_challenge)
        if lifetime_seconds <= 0 or lifetime_seconds > 600:
            raise OIDCProtocolError("authorization code lifetime must be 1-600 seconds")
        if not isinstance(subject, str) or not subject:
            raise OIDCProtocolError("authorization code subject is required")
        if value is not None and (not isinstance(value, str) or not value):
            raise OIDCProtocolError("authorization code value is required")
        return cls(
            value=value or secrets.token_urlsafe(32),
            client_id=client_id,
            redirect_uri=redirect_uri,
            subject=subject,
            scope=tuple(scope),
            nonce=nonce,
            code_challenge=code_challenge,
            expires_at=now + lifetime_seconds,
            code_challenge_method=code_challenge_method,
            auth_time=auth_time,
            acr=acr,
            amr=tuple(amr),
            user=user,
        )

    @property
    def code(self) -> str:
        """Authlib's conventional name for the opaque code value."""
        return self.value

    def get_redirect_uri(self) -> str:
        return self.redirect_uri

    def get_scope(self) -> str:
        return " ".join(self.scope)

    def get_nonce(self) -> str:
        return self.nonce

    def get_auth_time(self) -> int | None:
        return self.auth_time

    def get_acr(self) -> str | None:
        return self.acr

    def get_amr(self) -> list[str] | None:
        return list(self.amr) or None

    def is_expired(self, *, now: int | None = None) -> bool:
        return (int(time()) if now is None else now) >= self.expires_at

    def redeem(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        code_verifier: str,
        now: int,
    ) -> str:
        """Validate and mark this code as redeemed."""
        verifier = _validate_code_verifier(code_verifier)
        actual = create_s256_code_challenge(verifier)
        if (
            self.redeemed
            or self.is_expired(now=now)
            or self.client_id != client_id
            or self.redirect_uri != redirect_uri
            or self.code_challenge_method != "S256"
            or not compare_digest(actual, self.code_challenge)
        ):
            raise PermissionError("invalid authorization code")
        self.redeemed = True
        return self.subject


class AuthorizationCodeStore(Protocol):
    def save(self, code: AuthorizationCode) -> None: ...

    def get(self, value: str, *, client_id: str) -> AuthorizationCode | None: ...

    def consume(
        self,
        value: str,
        *,
        client_id: str,
        redirect_uri: str,
        code_verifier: str,
        now: int,
    ) -> AuthorizationCode: ...

    def has_nonce(
        self, client_id: str, nonce: str, *, now: int | None = None
    ) -> bool: ...


class MemoryAuthorizationCodeStore:
    """Thread-safe code store with atomic PKCE-checked consumption."""

    def __init__(self, *, now: Callable[[], int] | None = None) -> None:
        self._codes: dict[str, AuthorizationCode] = {}
        self._nonce_expiry: dict[tuple[str, str], int] = {}
        self._now = now or (lambda: int(time()))
        self._lock = threading.RLock()

    def _cleanup(self, now: int) -> None:
        expired_codes = [
            value
            for value, code in self._codes.items()
            if code.is_expired(now=now) and not code.redeemed
        ]
        for value in expired_codes:
            self._codes.pop(value, None)
        for key, expires_at in list(self._nonce_expiry.items()):
            if expires_at <= now:
                self._nonce_expiry.pop(key, None)

    def save(self, code: AuthorizationCode) -> None:
        with self._lock:
            now = self._now()
            self._cleanup(now)
            if code.value in self._codes:
                raise OIDCProtocolError("authorization code already exists")
            self._codes[code.value] = code
            self._nonce_expiry[(code.client_id, code.nonce)] = max(
                code.expires_at, now + 1
            )

    def get(self, value: str, *, client_id: str) -> AuthorizationCode | None:
        with self._lock:
            now = self._now()
            self._cleanup(now)
            code = self._codes.get(value)
            if (
                code is None
                or code.client_id != client_id
                or code.redeemed
                or code.is_expired(now=now)
            ):
                return None
            return code

    def consume(
        self,
        value: str,
        *,
        client_id: str,
        redirect_uri: str,
        code_verifier: str,
        now: int,
    ) -> AuthorizationCode:
        with self._lock:
            self._cleanup(now)
            code = self._codes.get(value)
            if code is None:
                raise PermissionError("invalid authorization code")
            code.redeem(
                client_id=client_id,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
                now=now,
            )
            self._codes.pop(value, None)
            return code

    def has_nonce(self, client_id: str, nonce: str, *, now: int | None = None) -> bool:
        with self._lock:
            current = self._now() if now is None else now
            expires_at = self._nonce_expiry.get((client_id, nonce))
            if expires_at is None or expires_at <= current:
                self._nonce_expiry.pop((client_id, nonce), None)
                return False
            return True


@dataclass(slots=True)
class TokenRecord:
    """Opaque bearer-token record; token values are excluded from repr output."""

    access_token: str = field(repr=False)
    client_id: str
    subject: str
    scope: str
    expires_at: int
    token_type: str = "Bearer"
    refresh_token: str | None = field(default=None, repr=False)
    refresh_expires_at: int | None = field(default=None, repr=False)
    user: object | None = field(default=None, repr=False, compare=False)
    client: OIDCClient | None = field(default=None, repr=False, compare=False)
    revoked: bool = False

    def get_scope(self) -> str:
        return self.scope

    def get_expires_in(self) -> int:
        return max(0, self.expires_at - int(time()))

    def is_expired(self) -> bool:
        return int(time()) >= self.expires_at

    def is_revoked(self) -> bool:
        return self.revoked

    def check_client(self, client: OIDCClient) -> bool:
        return client.get_client_id() == self.client_id

    def get_client(self) -> OIDCClient:
        if self.client is not None:
            return self.client
        return OIDCClient(
            client_id=self.client_id,
            redirect_uris=("https://invalid.local/unused",),
        )

    def get_user(self) -> object | None:
        return self.user


class TokenStore(Protocol):
    def save(
        self,
        token: Mapping[str, object],
        *,
        client_id: str,
        subject: str,
        now: int,
        user: object | None = None,
        client: OIDCClient | None = None,
    ) -> TokenRecord: ...

    def get_access_token(
        self, access_token: str, *, now: int | None = None
    ) -> TokenRecord | None: ...

    def revoke_access_token(self, access_token: str) -> bool: ...


class MemoryTokenStore:
    """Thread-safe in-memory bearer store used by examples and tests."""

    def __init__(self) -> None:
        self._tokens: dict[str, TokenRecord] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _key(value: str) -> str:
        return sha256(value.encode("utf-8")).hexdigest()

    def save(
        self,
        token: Mapping[str, object],
        *,
        client_id: str,
        subject: str,
        now: int,
        user: object | None = None,
        client: OIDCClient | None = None,
    ) -> TokenRecord:
        access_token = token.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise OIDCProtocolError("token generator did not return an access token")
        token_type = str(token.get("token_type", "Bearer"))
        if token_type.casefold() != "bearer":
            raise OIDCProtocolError("only Bearer access tokens are supported")
        raw_scope = token.get("scope")
        scope = _scope_string(
            raw_scope if isinstance(raw_scope, (str, list, tuple)) else None
        )
        raw_expires = token.get("expires_in")
        if raw_expires is None:
            raw_expires_at = token.get("expires_at")
            try:
                expires_at = (
                    int(raw_expires_at)
                    if isinstance(raw_expires_at, (str, int, float))
                    else now
                )
            except (TypeError, ValueError) as error:
                raise OIDCProtocolError(
                    "token expires_at must be an integer"
                ) from error
        else:
            try:
                expires_at = (
                    now + int(raw_expires)
                    if isinstance(raw_expires, (str, int, float))
                    else now
                )
            except (TypeError, ValueError) as error:
                raise OIDCProtocolError(
                    "token expires_in must be an integer"
                ) from error
        if expires_at <= now:
            raise OIDCProtocolError("access token lifetime must be positive")
        refresh_token = token.get("refresh_token")
        if refresh_token is not None and not isinstance(refresh_token, str):
            raise OIDCProtocolError("refresh_token must be a string")
        record = TokenRecord(
            access_token=access_token,
            client_id=client_id,
            subject=subject,
            scope=scope,
            expires_at=expires_at,
            token_type="Bearer",
            refresh_token=refresh_token,
            user=user,
            client=client,
        )
        with self._lock:
            self._tokens[self._key(access_token)] = record
        return record

    def get_access_token(
        self, access_token: str, *, now: int | None = None
    ) -> TokenRecord | None:
        if not isinstance(access_token, str) or not access_token:
            return None
        with self._lock:
            record = self._tokens.get(self._key(access_token))
            current = int(time()) if now is None else now
            if record is None or record.revoked or current >= record.expires_at:
                return None
            return record

    def revoke_access_token(self, access_token: str) -> bool:
        with self._lock:
            record = self._tokens.get(self._key(access_token))
            if record is None:
                return False
            record.revoked = True
            return True


UserSubject = Callable[[object], str]
UserClaims = Callable[[object, tuple[str, ...]], Mapping[str, object]]
UserResolver = Callable[[str], object | None]
UserActive = Callable[[object], bool]
AuthenticationTime = Callable[[object], int | None]
AuthenticationAMR = Callable[[object], Sequence[str]]
AuthenticationACR = Callable[[object], str | None]


def default_user_subject(user: object) -> str:
    value = getattr(user, "user_id", None)
    if not isinstance(value, str) or not value:
        raise OIDCProtocolError("OIDC user adapter must provide a non-empty user_id")
    return value


def default_user_claims(user: object, scope: tuple[str, ...]) -> Mapping[str, object]:
    """Project only standard claims available on the supplied user object."""
    subject = default_user_subject(user)
    claims: dict[str, object] = {"sub": subject}
    display_name = getattr(user, "display_name", None) or getattr(user, "name", None)
    if "profile" in scope and isinstance(display_name, str) and display_name:
        claims["name"] = display_name
    email = getattr(user, "email", None)
    if "email" in scope and isinstance(email, str) and email:
        claims["email"] = email
        email_verified = getattr(user, "email_verified", None)
        if isinstance(email_verified, bool):
            claims["email_verified"] = email_verified
    return claims


def default_user_active(user: object) -> bool:
    return bool(getattr(user, "is_active", True))


@dataclass(frozen=True, slots=True)
class OIDCUserAdapter:
    """Host-owned mapping between a verified local user and OIDC claims."""

    subject: UserSubject = default_user_subject
    claims: UserClaims = default_user_claims
    resolve: UserResolver | None = None
    active: UserActive = default_user_active
    authentication_time: AuthenticationTime = lambda _user: None
    amr: AuthenticationAMR = lambda _user: ("webauthn",)
    acr: AuthenticationACR = lambda _user: None


class SigningKeyStore(Protocol):
    """Signing-key seam; implementations must retain private keys durably."""

    def current_private_key(self) -> Any: ...

    def public_jwks(self) -> Mapping[str, object]: ...


class OIDCProvider:
    """Framework-neutral provider state and host/user mapping policy."""

    def __init__(
        self,
        config: OIDCProviderConfig,
        *,
        clients: Iterable[OIDCClient],
        codes: AuthorizationCodeStore | None = None,
        tokens: TokenStore | None = None,
        signing_keys: SigningKeyStore | None = None,
        users: OIDCUserAdapter | None = None,
        authorization_code_lifetime: int = 300,
        access_token_lifetime: int = 600,
        id_token_lifetime: int = 600,
        allow_refresh_tokens: bool = False,
    ) -> None:
        if not 1 <= authorization_code_lifetime <= 600:
            raise OIDCConfigurationError(
                "authorization_code_lifetime must be between 1 and 600 seconds"
            )
        if not 1 <= access_token_lifetime <= 3600:
            raise OIDCConfigurationError(
                "access_token_lifetime must be between 1 and 3600 seconds"
            )
        if not 1 <= id_token_lifetime <= 3600:
            raise OIDCConfigurationError(
                "id_token_lifetime must be between 1 and 3600 seconds"
            )
        if allow_refresh_tokens:
            raise OIDCConfigurationError(
                "refresh tokens are not implemented in the first provider profile"
            )
        client_list = tuple(clients)
        client_map = {client.client_id: client for client in client_list}
        if len(client_map) != len(client_list):
            raise OIDCConfigurationError("client_id values must be unique")
        if not client_map:
            raise OIDCConfigurationError("at least one OIDC client is required")
        self.config = config
        self.clients = client_map
        self.codes = codes or MemoryAuthorizationCodeStore()
        self.tokens = tokens or MemoryTokenStore()
        self.signing_keys = signing_keys
        self.users = users or OIDCUserAdapter()
        self.authorization_code_lifetime = authorization_code_lifetime
        self.access_token_lifetime = access_token_lifetime
        self.id_token_lifetime = id_token_lifetime

    def query_client(self, client_id: str) -> OIDCClient | None:
        return self.clients.get(client_id)

    def subject_for(self, user: object) -> str:
        subject = self.users.subject(user)
        if not isinstance(subject, str) or not subject:
            raise OIDCProtocolError("OIDC subject adapter returned an invalid subject")
        return subject

    def resolve_subject(
        self, subject: str, *, fallback: object | None = None
    ) -> object | None:
        if self.users.resolve is not None:
            return self.users.resolve(subject)
        if fallback is not None and self.subject_for(fallback) == subject:
            return fallback
        return None

    def is_active(self, user: object) -> bool:
        return self.users.active(user)

    def claims_for(self, user: object, scope: str | Iterable[str]) -> dict[str, object]:
        scopes = _scope_tuple(scope)
        claims = dict(self.users.claims(user, scopes))
        subject = self.subject_for(user)
        claims["sub"] = subject
        if "openid" not in scopes:
            return {"sub": subject}
        allowed: set[str] = {"sub"}
        if "profile" in scopes:
            allowed.update(
                {
                    "name",
                    "given_name",
                    "family_name",
                    "middle_name",
                    "nickname",
                    "preferred_username",
                    "profile",
                    "picture",
                    "website",
                    "gender",
                    "birthdate",
                    "zoneinfo",
                    "locale",
                    "updated_at",
                }
            )
        if "email" in scopes:
            allowed.update({"email", "email_verified"})
        return {key: value for key, value in claims.items() if key in allowed}

    def authentication_time_for(self, user: object) -> int | None:
        return self.users.authentication_time(user)

    def amr_for(self, user: object) -> tuple[str, ...]:
        return tuple(self.users.amr(user))

    def acr_for(self, user: object) -> str | None:
        return self.users.acr(user)

    def metadata(self) -> dict[str, object]:
        return self.config.metadata()


__all__ = [
    "OIDC_SCOPE",
    "AuthenticationACR",
    "AuthenticationAMR",
    "AuthenticationTime",
    "AuthorizationCode",
    "AuthorizationCodeStore",
    "MemoryAuthorizationCodeStore",
    "MemoryTokenStore",
    "OIDCClient",
    "OIDCConfigurationError",
    "OIDCProtocolError",
    "OIDCProvider",
    "OIDCProviderConfig",
    "OIDCUserAdapter",
    "SigningKeyStore",
    "TokenRecord",
    "TokenStore",
    "create_s256_code_challenge",
    "default_user_active",
    "default_user_claims",
    "default_user_subject",
    "hash_client_secret",
    "validate_client_redirect",
]
