"""Optional FastAPI/Authlib adapter for the my-auth OpenID Provider.

Importing this module opts into the OIDC stack.  ``import my_auth`` and the
WebAuthn RP modules intentionally do not import FastAPI, Authlib, or joserfc.
The adapter keeps HTTP concerns thin and leaves user lookup, account status,
consent, and session transport with the host application.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from time import time
from typing import Any, Literal, TypeVar, cast
from urllib.parse import parse_qs, urlencode, urlsplit

from authlib.common.security import generate_token
from authlib.consts import default_json_headers
from authlib.oauth2.rfc6749 import (
    AuthorizationCodeGrant,
    AuthorizationServer,
    InvalidGrantError,
    InvalidRequestError,
    OAuth2Error,
    OAuth2Request,
)
from authlib.oauth2.rfc6749.hooks import hooked
from authlib.oauth2.rfc6750 import BearerTokenGenerator
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oidc.core import OpenIDCode, UserInfo
from authlib.oidc.core.errors import LoginRequiredError
from fastapi import APIRouter, Request, Response
from joserfc.jwk import Key, KeySet, RSAKey
from starlette.responses import JSONResponse, RedirectResponse

from .oidc import (
    AuthorizationCode,
    OIDCClient,
    OIDCProtocolError,
    OIDCProvider,
)

T = TypeVar("T")
MaybeAwaitable = T | Awaitable[T]


@dataclass(frozen=True, slots=True)
class OIDCConsentContext:
    """Validated authorization data passed to the host consent policy."""

    client: OIDCClient
    scope: tuple[str, ...]
    redirect_uri: str
    state: str | None
    nonce: str
    prompt: str | None
    user: object


@dataclass(frozen=True, slots=True)
class OIDCProviderHooks:
    """Host-owned session, optional reauthentication, and consent callbacks."""

    get_session_user: Callable[[Request], MaybeAwaitable[object | None]]
    decide_consent: Callable[[Request, OIDCConsentContext], MaybeAwaitable[bool]]
    reauthenticate: Callable[[Request], MaybeAwaitable[object | None]] | None = None
    login_url: str | None = None

    def __post_init__(self) -> None:
        if self.login_url is None:
            return
        if not _same_origin_path(self.login_url):
            raise ValueError("login_url must be an application-relative path")


@dataclass(frozen=True, slots=True)
class OIDCPaths:
    """HTTP paths derived from the configured provider endpoint URLs."""

    discovery: str
    authorization: str
    token: str
    jwks: str
    userinfo: str | None
    revocation: str | None


class MemorySigningKeyStore:
    """Development signing-key store with public-only JWKS serialization.

    The private key is held in process memory and is therefore suitable for
    tests and demonstrations only. Production applications must implement the
    :class:`my_auth.oidc.SigningKeyStore` seam with durable protected storage.
    """

    def __init__(self, keys: Iterable[RSAKey]) -> None:
        values = tuple(keys)
        if not values:
            raise ValueError("at least one RSA signing key is required")
        for key in values:
            if not key.is_private:
                raise ValueError("signing key store requires private RSA keys")
            key.ensure_kid()
        self._keys = cast(list[RSAKey], list(values))

    @classmethod
    def generate(cls, *, key_size: int = 2048) -> MemorySigningKeyStore:
        key = RSAKey.generate_key(
            key_size,
            parameters={"use": "sig", "alg": "RS256"},
            private=True,
            auto_kid=True,
        )
        return cls((key,))

    def current_private_key(self) -> RSAKey:
        return self._keys[0]

    def private_keys(self) -> tuple[RSAKey, ...]:
        """Return the retained private keys for validation during rotation."""
        return tuple(self._keys)

    def public_jwks(self) -> dict[str, list[dict[str, object]]]:
        return cast(
            dict[str, list[dict[str, object]]],
            KeySet(cast(list[Key], self._keys)).as_dict(private=False),
        )

    def rotate(self, *, key_size: int = 2048) -> None:
        key = RSAKey.generate_key(
            key_size,
            parameters={"use": "sig", "alg": "RS256"},
            private=True,
            auto_kid=True,
        )
        self._keys.insert(0, key)


class _OAuth2Payload:
    def __init__(self, values: Mapping[str, list[str]]) -> None:
        self._values = {key: list(items) for key, items in values.items()}

    @property
    def data(self) -> dict[str, str]:
        return {key: items[0] for key, items in self._values.items() if items}

    @property
    def datalist(self) -> dict[str, list[str]]:
        return self._values

    @property
    def client_id(self) -> str | None:
        return self.data.get("client_id")

    @property
    def response_type(self) -> str | None:
        value = self.data.get("response_type")
        if value and " " in value:
            return " ".join(sorted(value.split()))
        return value

    @property
    def grant_type(self) -> str | None:
        return self.data.get("grant_type")

    @property
    def redirect_uri(self) -> str | None:
        return self.data.get("redirect_uri")

    @property
    def scope(self) -> str | None:
        return self.data.get("scope")

    @property
    def state(self) -> str | None:
        return self.data.get("state")


class _OAuth2Request(OAuth2Request):
    def __init__(
        self,
        *,
        method: str,
        uri: str,
        headers: Mapping[str, str],
        values: Mapping[str, list[str]],
    ) -> None:
        super().__init__(method=method, uri=uri, headers=headers)
        payload = _OAuth2Payload(values)
        self.payload = cast(Any, payload)
        self._form = payload.data

    @property
    def args(self) -> dict[str, str | None]:
        payload = cast(_OAuth2Payload, self.payload)
        return cast(dict[str, str | None], payload.data)

    @property
    def form(self) -> dict[str, str]:
        return self._form

    @property
    def body(self) -> Mapping[str, str]:
        return self._form


def _query_values(request: Request) -> dict[str, list[str]]:
    values: defaultdict[str, list[str]] = defaultdict(list)
    for key, value in request.query_params.multi_items():
        values[key].append(value)
    return dict(values)


def _form_values(raw: bytes) -> dict[str, list[str]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InvalidRequestError("Request form must be UTF-8") from error
    parsed = parse_qs(text, keep_blank_values=True, strict_parsing=False)
    return {key: list(values) for key, values in parsed.items()}


def _path(url: str) -> str:
    value = urlsplit(url).path
    return value or "/"


def _paths(provider: OIDCProvider) -> OIDCPaths:
    config = provider.config
    return OIDCPaths(
        discovery=_path(config.discovery_endpoint),
        authorization=_path(config.authorization_endpoint),
        token=_path(config.token_endpoint),
        jwks=_path(config.jwks_uri),
        userinfo=_path(config.userinfo_endpoint)
        if config.userinfo_endpoint is not None
        else None,
        revocation=_path(config.revocation_endpoint)
        if config.revocation_endpoint is not None
        else None,
    )


class _ProviderAuthorizationCodeGrant(AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ("client_secret_basic", "none")

    def __init__(self, request: OAuth2Request, server: _ProviderAuthorizationServer):
        super().__init__(request, server)
        self.provider = server.provider

    def validate_authorization_request(self) -> str:
        redirect_uri = super().validate_authorization_request()
        payload = cast(_OAuth2Payload, self.request.payload)
        data = payload.data
        raw_scope = data.get("scope")
        if not raw_scope or "openid" not in raw_scope.split():
            raise InvalidRequestError(
                "The authorization request must include the openid scope.",
                redirect_uri=redirect_uri,
            )
        if data.get("code_challenge_method") != "S256":
            raise InvalidRequestError(
                "Only S256 code_challenge_method is supported.",
                redirect_uri=redirect_uri,
            )
        challenge = data.get("code_challenge")
        if not challenge:
            raise InvalidRequestError(
                "Missing 'code_challenge'.",
                redirect_uri=redirect_uri,
            )
        nonce = data.get("nonce")
        if not nonce:
            raise InvalidRequestError(
                "Missing 'nonce'.",
                redirect_uri=redirect_uri,
            )
        return redirect_uri

    def save_authorization_code(self, code: str, request: OAuth2Request) -> None:
        user = request.user
        if user is None or not self.provider.is_active(user):
            raise InvalidGrantError("The authenticated user is unavailable.")
        subject = self.provider.subject_for(user)
        payload = cast(_OAuth2Payload, request.payload)
        raw_scope = request.scope
        scope = (
            tuple(raw_scope.split()) if isinstance(raw_scope, str) else tuple(raw_scope)
        )
        auth_time = self.provider.authentication_time_for(user)
        if auth_time is None:
            auth_time = int(time())
        item = AuthorizationCode.issue(
            value=code,
            client_id=cast(OIDCClient, request.client).get_client_id(),
            redirect_uri=self.redirect_uri or cast(str, payload.redirect_uri),
            subject=subject,
            scope=scope,
            nonce=cast(str, payload.data["nonce"]),
            code_challenge=cast(str, payload.data["code_challenge"]),
            code_challenge_method="S256",
            now=int(time()),
            lifetime_seconds=self.provider.authorization_code_lifetime,
            auth_time=auth_time,
            acr=self.provider.acr_for(user),
            amr=self.provider.amr_for(user),
            user=user,
        )
        self.provider.codes.save(item)

    def query_authorization_code(
        self, code: str, client: object
    ) -> AuthorizationCode | None:
        if not isinstance(client, OIDCClient):
            return None
        return self.provider.codes.get(code, client_id=client.get_client_id())

    def delete_authorization_code(self, authorization_code: AuthorizationCode) -> None:
        # The provider consumes the code atomically before generating a token.
        # Authlib calls this hook in its default implementation; the custom
        # create_token_response below performs the actual deletion.
        del authorization_code

    def authenticate_user(self, authorization_code: AuthorizationCode) -> object | None:
        return self.provider.resolve_subject(
            authorization_code.subject,
            fallback=authorization_code.user,
        )

    @hooked
    def create_token_response(self) -> tuple[int, Any, list[tuple[str, str]]]:
        authorization_code = self.request.authorization_code
        if not isinstance(authorization_code, AuthorizationCode):
            raise InvalidGrantError("Invalid authorization code.")
        client = self.request.client
        if not isinstance(client, OIDCClient):
            raise InvalidGrantError("Invalid client.")
        verifier = self.request.form.get("code_verifier")
        if not isinstance(verifier, str):
            raise InvalidGrantError("Missing code verifier.")
        try:
            consumed = self.provider.codes.consume(
                authorization_code.value,
                client_id=client.get_client_id(),
                redirect_uri=cast(
                    str, cast(_OAuth2Payload, self.request.payload).redirect_uri
                ),
                code_verifier=verifier,
                now=int(time()),
            )
        except (OIDCProtocolError, PermissionError) as error:
            raise InvalidGrantError("Invalid authorization code.") from error

        user = self.authenticate_user(consumed)
        if user is None or not self.provider.is_active(user):
            raise InvalidGrantError("The authenticated user is unavailable.")
        self.request.user = user
        token = self.generate_token(
            user=user,
            scope=consumed.get_scope(),
            include_refresh_token=False,
            expires_in=self.provider.access_token_lifetime,
        )
        self.save_token(token)
        return (
            200,
            cast(Any, token),
            cast(list[tuple[str, str]], self.TOKEN_RESPONSE_HEADER),
        )


class _ProviderOpenIDCode(OpenIDCode):
    def __init__(self, provider: OIDCProvider):
        super().__init__(require_nonce=True)
        self.provider = provider

    def resolve_client_private_key(self, client: OIDCClient) -> RSAKey:
        del client
        if self.provider.signing_keys is None:
            raise RuntimeError("an OIDC signing-key store is required")
        return cast(RSAKey, self.provider.signing_keys.current_private_key())

    def get_client_algorithm(self, client: OIDCClient) -> Literal["RS256"]:
        del client
        return "RS256"

    def get_encode_header(self, client: OIDCClient) -> dict[str, str]:
        del client
        if self.provider.signing_keys is None:
            raise RuntimeError("an OIDC signing-key store is required")
        key = self.provider.signing_keys.current_private_key()
        kid = getattr(key, "kid", None)
        if not isinstance(kid, str) or not kid:
            raise RuntimeError("OIDC signing key has no kid")
        return {"alg": "RS256", "kid": kid}

    def get_client_claims(self, client: OIDCClient) -> dict[str, object]:
        return {
            "iss": self.provider.config.issuer,
            "aud": client.get_client_id(),
            "exp": int(time()) + self.provider.id_token_lifetime,
        }

    def exists_nonce(self, nonce: str, request: OAuth2Request) -> bool:
        return self.provider.codes.has_nonce(
            cast(str, cast(_OAuth2Payload, request.payload).client_id), nonce
        )

    def generate_user_info(self, user: object, scope: str) -> UserInfo:
        return UserInfo(self.provider.claims_for(user, scope))


class _ProviderAuthorizationServer(AuthorizationServer):
    def __init__(self, provider: OIDCProvider):
        super().__init__(scopes_supported=["openid", "profile", "email"])
        self.provider = provider
        self.register_token_generator("default", self._token_generator())
        self.register_grant(
            _ProviderAuthorizationCodeGrant,
            extensions=[CodeChallenge(required=True), _ProviderOpenIDCode(provider)],
        )

    def _token_generator(self) -> BearerTokenGenerator:
        def access_token_generator(**_kwargs: object) -> str:
            return generate_token(48)

        def expires_generator(_client: object, _grant_type: str) -> int:
            return self.provider.access_token_lifetime

        return BearerTokenGenerator(
            access_token_generator,
            refresh_token_generator=None,
            expires_generator=expires_generator,
        )

    def query_client(self, client_id: str) -> Any:
        return self.provider.query_client(client_id)

    def save_token(self, token: Mapping[str, object], request: OAuth2Request) -> None:
        client = request.client
        user = request.user
        if not isinstance(client, OIDCClient) or user is None:
            raise InvalidGrantError("The token subject is unavailable.")
        subject = self.provider.subject_for(user)
        self.provider.tokens.save(
            token,
            client_id=client.get_client_id(),
            subject=subject,
            now=int(time()),
            user=user,
            client=client,
        )

    def create_oauth2_request(self, request: object) -> OAuth2Request:
        if isinstance(request, OAuth2Request):
            return request
        raise TypeError("OIDC requests must be converted by the FastAPI adapter")

    def handle_response(
        self,
        status: int,
        body: object,
        headers: object,
    ) -> Response:
        if isinstance(headers, Mapping):
            response_headers = cast(Mapping[str, str], headers)
        else:
            response_headers = cast(
                Mapping[str, str],
                dict(cast(Iterable[tuple[str, str]], headers)),
            )
        if isinstance(body, Mapping):
            content: str | bytes = json.dumps(dict(body), separators=(",", ":"))
        elif isinstance(body, (str, bytes)):
            content = body
        else:
            content = str(body)
        return Response(content=content, status_code=status, headers=response_headers)

    def send_signal(self, name: str, *args: object, **kwargs: object) -> None:
        del name, args, kwargs


class OIDCProviderRouter:
    def __init__(
        self,
        *,
        provider: OIDCProvider,
        hooks: OIDCProviderHooks,
        max_body_bytes: int = 16 * 1024,
    ) -> None:
        if provider.signing_keys is None:
            raise ValueError("OIDC provider requires a signing-key store")
        if max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be positive")
        self.provider = provider
        self.hooks = hooks
        self.max_body_bytes = max_body_bytes
        self.server = _ProviderAuthorizationServer(provider)
        self.paths = _paths(provider)
        self.router = APIRouter()
        self._add_routes()

    def _add_routes(self) -> None:
        self.router.add_api_route(self.paths.discovery, self.discovery, methods=["GET"])
        self.router.add_api_route(
            self.paths.authorization, self.authorization, methods=["GET"]
        )
        self.router.add_api_route(self.paths.token, self.token, methods=["POST"])
        self.router.add_api_route(self.paths.jwks, self.jwks, methods=["GET"])
        if self.paths.userinfo is not None:
            self.router.add_api_route(
                self.paths.userinfo, self.userinfo, methods=["GET", "POST"]
            )
        if self.paths.revocation is not None:
            self.router.add_api_route(
                self.paths.revocation, self.revocation, methods=["POST"]
            )

    async def discovery(self) -> Response:
        return JSONResponse(self.provider.metadata(), headers=_json_headers())

    async def jwks(self) -> Response:
        if self.provider.signing_keys is None:  # pragma: no cover - constructor guard
            return JSONResponse({"keys": []}, status_code=503)
        return JSONResponse(
            self.provider.signing_keys.public_jwks(), headers=_json_headers()
        )

    async def authorization(self, request: Request) -> Response:
        values = _query_values(request)
        oauth_request = _OAuth2Request(
            method=request.method,
            uri=str(request.url),
            headers=request.headers,
            values=values,
        )
        session_user = await _maybe_await(self.hooks.get_session_user(request))
        if session_user is not None and not self.provider.is_active(session_user):
            return _oauth_json_error("login_required", status_code=401)
        try:
            grant = self.server.get_consent_grant(
                request=oauth_request,
                end_user=session_user,
            )
            if session_user is None:
                if _prompt_none(values):
                    raise LoginRequiredError(redirect_uri=grant.redirect_uri)
                if self.hooks.login_url:
                    return _login_redirect(self.hooks.login_url, _return_to(request))
                return _oauth_json_error("login_required", status_code=401)
            user = session_user
            if _requires_reauthentication(values):
                if self.hooks.reauthenticate is None:
                    raise LoginRequiredError(redirect_uri=grant.redirect_uri)
                user = await _maybe_await(self.hooks.reauthenticate(request))
                if user is None or not self.provider.is_active(user):
                    raise LoginRequiredError(redirect_uri=grant.redirect_uri)
            _validate_max_age(self.provider, values, user, grant.redirect_uri)
            scope = tuple(cast(str, grant.request.scope).split())
            context = OIDCConsentContext(
                client=cast(OIDCClient, grant.request.client),
                scope=scope,
                redirect_uri=cast(str, grant.redirect_uri),
                state=cast(str | None, grant.request.payload.state),
                nonce=cast(str, grant.request.payload.data["nonce"]),
                prompt=cast(str | None, grant.request.payload.data.get("prompt")),
                user=user,
            )
            consent = await _maybe_await(self.hooks.decide_consent(request, context))
            return _as_response(
                self.server.create_authorization_response(
                    request=oauth_request,
                    grant_user=user if consent else None,
                    grant=grant,
                )
            )
        except OAuth2Error as error:
            if error.state is None:
                error.state = cast(str | None, values.get("state", [None])[0])
            return _as_response(self.server.handle_error_response(oauth_request, error))

    async def token(self, request: Request) -> Response:
        values: dict[str, list[str]] = {}
        raw = await request.body()
        if len(raw) > self.max_body_bytes:
            return _oauth_json_error("invalid_request", status_code=400)
        try:
            values = _form_values(raw)
            oauth_request = _OAuth2Request(
                method=request.method,
                uri=str(request.url),
                headers=request.headers,
                values=values,
            )
            return _as_response(self.server.create_token_response(oauth_request))
        except OAuth2Error as error:
            return _as_response(
                self.server.handle_error_response(
                    _OAuth2Request(
                        method=request.method,
                        uri=str(request.url),
                        headers=request.headers,
                        values=values if "values" in locals() else {},
                    ),
                    error,
                )
            )
        except UnicodeDecodeError:
            return _oauth_json_error("invalid_request", status_code=400)

    async def userinfo(self, request: Request) -> Response:
        token = await _bearer_access_token(request, max_body_bytes=self.max_body_bytes)
        if token is None:
            return _oauth_json_error(
                "invalid_token", status_code=401, www_authenticate=True
            )
        record = self.provider.tokens.get_access_token(token)
        if record is None or record.token_type.casefold() != "bearer":
            return _oauth_json_error(
                "invalid_token", status_code=401, www_authenticate=True
            )
        if "openid" not in record.scope.split():
            return _oauth_json_error(
                "insufficient_scope", status_code=403, www_authenticate=True
            )
        user = self.provider.resolve_subject(record.subject, fallback=record.user)
        if user is None or not self.provider.is_active(user):
            return _oauth_json_error(
                "invalid_token", status_code=401, www_authenticate=True
            )
        return JSONResponse(
            self.provider.claims_for(user, record.scope),
            headers=_json_headers(),
        )

    async def revocation(self, request: Request) -> Response:
        raw = await request.body()
        if len(raw) > self.max_body_bytes:
            return _oauth_json_error("invalid_request", status_code=400)
        try:
            values = _form_values(raw)
        except (UnicodeDecodeError, ValueError):
            return _oauth_json_error("invalid_request", status_code=400)
        token = values.get("token", [""])[0]
        if not token:
            return _oauth_json_error("invalid_request", status_code=400)
        client_id = values.get("client_id", [None])[0]
        client = self.provider.query_client(cast(str, client_id)) if client_id else None
        if client is None or not client.check_endpoint_auth_method(
            "none", "revocation"
        ):
            return _oauth_json_error("invalid_client", status_code=401)
        self.provider.tokens.revoke_access_token(token)
        return Response(status_code=200, headers=_json_headers())


def build_oidc_fastapi_plugin(
    *,
    provider: OIDCProvider,
    hooks: OIDCProviderHooks,
    max_body_bytes: int = 16 * 1024,
) -> APIRouter:
    """Build an explicit FastAPI router for the configured OIDC provider."""
    return OIDCProviderRouter(
        provider=provider,
        hooks=hooks,
        max_body_bytes=max_body_bytes,
    ).router


def _requires_reauthentication(values: Mapping[str, list[str]]) -> bool:
    prompt = values.get("prompt", [""])[0]
    return "login" in prompt.split()


def _prompt_none(values: Mapping[str, list[str]]) -> bool:
    prompt = values.get("prompt", [""])[0]
    return "none" in prompt.split()


def _same_origin_path(value: str) -> bool:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or value.startswith("//")
    ):
        return False
    if "\\" in value or " " in value:
        return False
    parts = urlsplit(value)
    return not parts.scheme and not parts.netloc and not parts.fragment


def _return_to(request: Request) -> str:
    path = request.url.path
    query = str(request.url.query)
    if not path.startswith("/") or path.startswith("//"):
        return "/"
    if query:
        return f"{path}?{query}"
    return path


def _login_redirect(login_url: str, next_path: str) -> RedirectResponse:
    parts = urlsplit(login_url)
    existing = parse_qs(parts.query, keep_blank_values=True)
    existing["next"] = [next_path]
    query = urlencode(existing, doseq=True)
    location = parts.path + (f"?{query}" if query else "")
    return RedirectResponse(location, status_code=302)


def _validate_max_age(
    provider: OIDCProvider,
    values: Mapping[str, list[str]],
    user: object,
    redirect_uri: str,
) -> None:
    raw = values.get("max_age", [None])[0]
    if raw is None:
        return
    try:
        max_age = int(raw)
    except (TypeError, ValueError) as error:
        raise InvalidRequestError(
            "max_age must be a non-negative integer", redirect_uri=redirect_uri
        ) from error
    if max_age < 0:
        raise InvalidRequestError(
            "max_age must be a non-negative integer", redirect_uri=redirect_uri
        )
    authenticated_at = provider.authentication_time_for(user)
    if authenticated_at is None or int(time()) - authenticated_at > max_age:
        raise LoginRequiredError(redirect_uri=redirect_uri)


def _as_response(result: object) -> Response:
    if isinstance(result, Response):
        return result
    if not isinstance(result, tuple) or len(result) != 3:
        raise TypeError("Authlib returned an invalid response")
    status_code, body, headers = result
    if not isinstance(status_code, int):
        raise TypeError("Authlib returned an invalid status code")
    if not isinstance(headers, list):
        headers = list(headers)
    response_headers = {key: value for key, value in headers}
    if isinstance(body, Mapping):
        content: str | bytes = json.dumps(dict(body), separators=(",", ":"))
    elif isinstance(body, (str, bytes)):
        content = body
    else:
        content = str(body)
    return Response(content=content, status_code=status_code, headers=response_headers)


def _json_headers() -> dict[str, str]:
    return {key: value for key, value in default_json_headers}


def _oauth_json_error(
    error: str,
    *,
    status_code: int,
    www_authenticate: bool = False,
) -> JSONResponse:
    headers = _json_headers()
    if www_authenticate:
        headers["WWW-Authenticate"] = f'Bearer error="{error}"'
    return JSONResponse({"error": error}, status_code=status_code, headers=headers)


async def _bearer_access_token(request: Request, *, max_body_bytes: int) -> str | None:
    authorization = request.headers.get("Authorization", "")
    parts = authorization.split()
    header_token = (
        parts[1] if len(parts) == 2 and parts[0].casefold() == "bearer" else None
    )
    body_token: str | None = None
    if request.method == "POST":
        raw = await request.body()
        if len(raw) > max_body_bytes:
            return None
        try:
            values = _form_values(raw)
        except (UnicodeDecodeError, InvalidRequestError):
            return None
        candidate = values.get("access_token", [None])[0]
        if isinstance(candidate, str) and candidate:
            body_token = candidate
    if header_token and body_token:
        return None
    return header_token or body_token


async def _maybe_await(value: MaybeAwaitable[T]) -> T:
    if isinstance(value, Awaitable):
        return cast(T, await value)
    return cast(T, value)


__all__ = [
    "MemorySigningKeyStore",
    "OIDCConsentContext",
    "OIDCPaths",
    "OIDCProviderHooks",
    "OIDCProviderRouter",
    "build_oidc_fastapi_plugin",
]
