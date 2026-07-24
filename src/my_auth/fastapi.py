from __future__ import annotations

import inspect
import logging
import os
import secrets
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Literal, Protocol, TypeVar, cast

from fastapi import APIRouter, HTTPException, Request, Response
from starlette.responses import JSONResponse, RedirectResponse
from webauthn.helpers.exceptions import WebAuthnException

from .passkeys import (
    AuthenticationResult,
    ChallengeNotFound,
    ChallengeStore,
    CredentialNotFound,
    CredentialStore,
    PasskeyConfig,
    PasskeyCredential,
    PasskeyService,
    PasskeyUser,
    UserHandleMismatch,
    VerifiedRegistration,
)

logger = logging.getLogger(__name__)
AuthUser = PasskeyUser
T = TypeVar("T")
CookieSameSite = Literal["lax", "strict", "none"]
MaybeAwaitable = T | Awaitable[T]


class RenderRegister(Protocol):
    def __call__(
        self, request: Request, *, bootstrap: bool
    ) -> MaybeAwaitable[Response]: ...


class _PasskeyServiceAPI(Protocol):
    config: PasskeyConfig

    def begin_authentication(
        self,
        *,
        flow_id: str,
        allow_credentials: Iterable[PasskeyCredential] | None = None,
    ) -> dict[str, object]: ...

    def finish_authentication(
        self,
        *,
        flow_id: str,
        credential: Mapping[str, object] | str,
        require_user_handle: bool = True,
    ) -> AuthenticationResult: ...

    def begin_registration(
        self, *, flow_id: str, user: PasskeyUser
    ) -> dict[str, object]: ...

    def verify_registration(
        self, *, flow_id: str, credential: Mapping[str, object] | str
    ) -> VerifiedRegistration: ...


@dataclass(frozen=True)
class PasskeyPaths:
    login_page: str = "/login"
    register_page: str = "/register"
    logout: str = "/logout"
    login_options: str = "/api/auth/login/options"
    login_verify: str = "/api/auth/login/verify"
    register_options: str = "/api/auth/register/options"
    register_verify: str = "/api/auth/register/verify"


@dataclass(frozen=True)
class PasskeyCookies:
    authentication_challenge: str = "passkey_authentication_challenge"
    registration_challenge: str = "passkey_registration_challenge"
    path: str = "/"
    secure: bool = True
    httponly: bool = True
    samesite: str = "lax"


@dataclass(frozen=True)
class PasskeyRouteHooks:
    get_session_user: Callable[[Request], MaybeAwaitable[AuthUser | None]]
    prepare_registration: Callable[[Request, str], MaybeAwaitable[PasskeyUser]]
    complete_registration: Callable[
        [Request, VerifiedRegistration], MaybeAwaitable[AuthUser | None]
    ]
    get_auth_user: Callable[[str], MaybeAwaitable[AuthUser | None]]
    login: Callable[[Response, Request, AuthUser], MaybeAwaitable[None]]
    logout: Callable[[Response, Request], MaybeAwaitable[None]]
    registration_allowed: Callable[[Request], MaybeAwaitable[bool]]
    render_login: Callable[[Request], MaybeAwaitable[Response]]
    render_register: RenderRegister
    after_register: Callable[
        [Request, AuthUser, PasskeyCredential], MaybeAwaitable[None]
    ] = field(default=lambda _request, _user, _credential: None)
    after_login: Callable[
        [Request, AuthUser, PasskeyCredential], MaybeAwaitable[None]
    ] = field(default=lambda _request, _user, _credential: None)


PasskeyFastAPIHooks = PasskeyRouteHooks


@dataclass(frozen=True)
class PasskeyFastAPISettings:
    rp_id: str
    rp_name: str
    origin: str
    timeout_ms: int = 60_000
    challenge_ttl_seconds: int = 300
    user_verification: Literal["required", "preferred", "discouraged"] = "required"
    paths: PasskeyPaths = PasskeyPaths()
    cookies: PasskeyCookies = PasskeyCookies()

    @classmethod
    def from_env(
        cls, environ: Mapping[str, str] | None = None, *, prefix: str = "PASSKEY_"
    ) -> "PasskeyFastAPISettings":
        env = os.environ if environ is None else environ
        settings = cls(
            rp_id=_required_env(env, prefix, "RP_ID"),
            rp_name=_required_env(env, prefix, "RP_NAME"),
            origin=_required_env(env, prefix, "ORIGIN"),
            timeout_ms=_int_env(env, prefix, "TIMEOUT_MS", 60_000),
            challenge_ttl_seconds=_int_env(env, prefix, "CHALLENGE_TTL_SECONDS", 300),
            user_verification=_user_verification_env(env, prefix),
            paths=PasskeyPaths(
                login_page=_env(env, prefix, "LOGIN_PAGE", PasskeyPaths.login_page),
                register_page=_env(
                    env, prefix, "REGISTER_PAGE", PasskeyPaths.register_page
                ),
                logout=_env(env, prefix, "LOGOUT_PATH", PasskeyPaths.logout),
                login_options=_env(
                    env, prefix, "LOGIN_OPTIONS_PATH", PasskeyPaths.login_options
                ),
                login_verify=_env(
                    env, prefix, "LOGIN_VERIFY_PATH", PasskeyPaths.login_verify
                ),
                register_options=_env(
                    env, prefix, "REGISTER_OPTIONS_PATH", PasskeyPaths.register_options
                ),
                register_verify=_env(
                    env, prefix, "REGISTER_VERIFY_PATH", PasskeyPaths.register_verify
                ),
            ),
            cookies=PasskeyCookies(
                authentication_challenge=_env(
                    env,
                    prefix,
                    "AUTHENTICATION_CHALLENGE_COOKIE",
                    PasskeyCookies.authentication_challenge,
                ),
                registration_challenge=_env(
                    env,
                    prefix,
                    "REGISTRATION_CHALLENGE_COOKIE",
                    PasskeyCookies.registration_challenge,
                ),
                path=_env(env, prefix, "COOKIE_PATH", PasskeyCookies.path),
                secure=_bool_env(env, prefix, "COOKIE_SECURE", True),
                httponly=_bool_env(env, prefix, "COOKIE_HTTPONLY", True),
                samesite=_env(env, prefix, "COOKIE_SAMESITE", PasskeyCookies.samesite),
            ),
        )
        _ = settings.passkey_config()
        return settings

    def passkey_config(self) -> PasskeyConfig:
        return PasskeyConfig(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            origin=self.origin,
            timeout_ms=self.timeout_ms,
            challenge_ttl_seconds=self.challenge_ttl_seconds,
            user_verification=self.user_verification,
        )


def build_passkey_fastapi_plugin(
    *,
    settings: PasskeyFastAPISettings,
    credentials: CredentialStore,
    challenges: ChallengeStore,
    hooks: PasskeyFastAPIHooks,
) -> APIRouter:
    service = PasskeyService(
        config=settings.passkey_config(), challenges=challenges, credentials=credentials
    )
    return PasskeyAuthRouter(
        service=service, hooks=hooks, paths=settings.paths, cookies=settings.cookies
    ).router


class PasskeyAuthRouter:
    def __init__(
        self,
        *,
        service: _PasskeyServiceAPI,
        hooks: PasskeyRouteHooks,
        paths: PasskeyPaths | None = None,
        cookies: PasskeyCookies | None = None,
    ) -> None:
        self.service: _PasskeyServiceAPI = service
        self.hooks: PasskeyRouteHooks = hooks
        self.paths: PasskeyPaths = paths or PasskeyPaths()
        self.cookies: PasskeyCookies = cookies or PasskeyCookies()
        self.router: APIRouter = APIRouter()
        self._add_routes()

    def _add_routes(self) -> None:
        self.router.add_api_route(
            self.paths.login_page, self.login_page, methods=["GET"]
        )
        self.router.add_api_route(
            self.paths.register_page, self.register_page, methods=["GET"]
        )
        self.router.add_api_route(self.paths.logout, self.logout, methods=["POST"])
        self.router.add_api_route(
            self.paths.login_options, self.login_options, methods=["POST"]
        )
        self.router.add_api_route(
            self.paths.login_verify, self.login_verify, methods=["POST"]
        )
        self.router.add_api_route(
            self.paths.register_options, self.register_options, methods=["POST"]
        )
        self.router.add_api_route(
            self.paths.register_verify, self.register_verify, methods=["POST"]
        )

    async def login_page(self, request: Request) -> Response:
        return await _maybe_await(self.hooks.render_login(request))

    async def register_page(self, request: Request) -> Response:
        user = await _maybe_await(self.hooks.get_session_user(request))
        return await _maybe_await(
            self.hooks.render_register(request, bootstrap=user is None)
        )

    async def login_options(self) -> Response:
        flow_id = self._new_flow_id()
        response = JSONResponse(self.service.begin_authentication(flow_id=flow_id))
        self._set_cookie(response, self.cookies.authentication_challenge, flow_id)
        return response

    async def login_verify(self, request: Request) -> Response:
        flow_id = self._challenge_cookie(request, self.cookies.authentication_challenge)
        credential = _without_legacy_user_handle(await _json_body(request))
        try:
            result = self.service.finish_authentication(
                flow_id=flow_id, credential=credential, require_user_handle=False
            )
        except AUTH_ERRORS as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        user = await _maybe_await(self.hooks.get_auth_user(result.user.user_id))
        if user is None:
            raise HTTPException(
                status_code=403, detail="authenticated user is not allowed"
            )
        response = JSONResponse({"ok": True})
        self._delete_cookie(response, self.cookies.authentication_challenge)
        await _maybe_await(self.hooks.login(response, request, user))
        try:
            await _maybe_await(self.hooks.after_login(request, user, result.credential))
        except Exception:
            logger.exception("after_login observer failed")
        return response

    async def register_options(self, request: Request) -> Response:
        if not await _maybe_await(self.hooks.registration_allowed(request)):
            raise HTTPException(
                status_code=403, detail="passkey registration is not allowed"
            )
        session_user = await _maybe_await(self.hooks.get_session_user(request))
        user = session_user or await _maybe_await(
            self.hooks.prepare_registration(
                request, _registration_display_name(await _json_body(request))
            )
        )
        flow_id = self._new_flow_id()
        response = JSONResponse(
            self.service.begin_registration(flow_id=flow_id, user=user)
        )
        self._set_cookie(response, self.cookies.registration_challenge, flow_id)
        return response

    async def register_verify(self, request: Request) -> Response:
        flow_id = self._challenge_cookie(request, self.cookies.registration_challenge)
        if not await _maybe_await(self.hooks.registration_allowed(request)):
            raise HTTPException(
                status_code=403, detail="passkey registration is not allowed"
            )
        try:
            result = self.service.verify_registration(
                flow_id=flow_id, credential=await _json_body(request)
            )
        except AUTH_ERRORS as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        try:
            user = await _maybe_await(self.hooks.complete_registration(request, result))
        except Exception:
            logger.exception("registration completion failed")
            raise HTTPException(
                status_code=500, detail="registration could not be completed"
            )
        if user is None:
            raise HTTPException(
                status_code=403, detail="registered user is not allowed"
            )
        response = JSONResponse({"ok": True})
        self._delete_cookie(response, self.cookies.registration_challenge)
        await _maybe_await(self.hooks.login(response, request, user))
        try:
            await _maybe_await(
                self.hooks.after_register(request, user, result.credential)
            )
        except Exception:
            logger.exception("after_register observer failed")
        return response

    async def logout(self, request: Request) -> Response:
        response = RedirectResponse(self.paths.login_page, status_code=303)
        await _maybe_await(self.hooks.logout(response, request))
        self._delete_cookie(response, self.cookies.authentication_challenge)
        self._delete_cookie(response, self.cookies.registration_challenge)
        return response

    def _new_flow_id(self) -> str:
        return secrets.token_urlsafe(32)

    def _challenge_cookie(self, request: Request, name: str) -> str:
        value = request.cookies.get(name)
        if not value:
            raise HTTPException(status_code=400, detail="missing passkey challenge")
        return value

    def _set_cookie(self, response: Response, key: str, value: str) -> None:
        response.set_cookie(
            key,
            value,
            max_age=self.service.config.challenge_ttl_seconds,
            path=self.cookies.path,
            secure=self.cookies.secure,
            httponly=self.cookies.httponly,
            samesite=cast(CookieSameSite, self.cookies.samesite),
        )

    def _delete_cookie(self, response: Response, key: str) -> None:
        response.delete_cookie(
            key,
            path=self.cookies.path,
            secure=self.cookies.secure,
            httponly=self.cookies.httponly,
            samesite=cast(CookieSameSite, self.cookies.samesite),
        )


async def _maybe_await(value: MaybeAwaitable[T]) -> T:
    if inspect.isawaitable(value):
        return cast(T, await value)
    return cast(T, value)


async def _json_body(request: Request) -> dict[str, object]:
    try:
        value: object = cast(object, await request.json())
    except Exception as error:
        raise HTTPException(status_code=400, detail="invalid JSON body") from error
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="JSON object body is required")
    return cast(dict[str, object], value)


def _registration_display_name(body: Mapping[str, object]) -> str:
    value = body.get("display_name") or body.get("displayName") or body.get("name")
    if not isinstance(value, str) or not value.strip():
        raise HTTPException(status_code=400, detail="display_name is required")
    return value.strip()


def _without_legacy_user_handle(credential: dict[str, object]) -> dict[str, object]:
    response = credential.get("response")
    if not isinstance(response, dict) or "userHandle" not in response:
        return credential
    copied = dict(credential)
    copied_response = dict(cast(dict[str, object], response))
    _ = copied_response.pop("userHandle", None)
    copied["response"] = copied_response
    return copied


def _env(env: Mapping[str, str], prefix: str, name: str, default: T) -> str | T:
    return env.get(f"{prefix}{name}", default)


def _user_verification_env(
    env: Mapping[str, str], prefix: str
) -> Literal["required", "preferred", "discouraged"]:
    value = _env(env, prefix, "USER_VERIFICATION", "required")
    if value not in {"required", "preferred", "discouraged"}:
        raise ValueError(f"{prefix}USER_VERIFICATION is invalid")
    return cast(Literal["required", "preferred", "discouraged"], value)


def _required_env(env: Mapping[str, str], prefix: str, name: str) -> str:
    value = _env(env, prefix, name, None)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{prefix}{name} is required")
    return value.strip()


def _int_env(env: Mapping[str, str], prefix: str, name: str, default: int) -> int:
    value = _env(env, prefix, name, None)
    if value is None:
        return default
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{prefix}{name} must be an integer") from error


def _bool_env(env: Mapping[str, str], prefix: str, name: str, default: bool) -> bool:
    value = _env(env, prefix, name, None)
    if value is None:
        return default
    lowered = str(value).lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{prefix}{name} must be a boolean")


AUTH_ERRORS = (
    ChallengeNotFound,
    CredentialNotFound,
    UserHandleMismatch,
    WebAuthnException,
)
__all__ = [
    "AuthUser",
    "PasskeyAuthRouter",
    "PasskeyCookies",
    "PasskeyFastAPIHooks",
    "PasskeyFastAPISettings",
    "PasskeyPaths",
    "PasskeyRouteHooks",
    "build_passkey_fastapi_plugin",
]
