from __future__ import annotations

import inspect
import os
import secrets
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, TypeVar

from fastapi import APIRouter, HTTPException, Request, Response
from starlette.responses import JSONResponse, RedirectResponse
from webauthn.helpers.exceptions import WebAuthnException

from .passkeys import (
    ChallengeNotFound,
    ChallengeStore,
    CredentialNotFound,
    CredentialStore,
    PasskeyConfig,
    PasskeyCredential,
    PasskeyService,
    PasskeyUser,
    UserHandleMismatch,
)

AuthUser = PasskeyUser

T = TypeVar("T")
MaybeAwaitable = T | Awaitable[T]


class RenderRegister(Protocol):
    def __call__(self, request: Request, *, bootstrap: bool) -> MaybeAwaitable[Response]: ...


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
    challenge: str = "passkey_challenge"
    register_name: str = "passkey_register_name"
    path: str = "/"
    secure: bool = True
    httponly: bool = True
    samesite: str = "lax"


@dataclass(frozen=True)
class PasskeyRouteHooks:
    get_session_user: Callable[[Request], MaybeAwaitable[AuthUser | None]]
    make_registration_user: Callable[[Request, str], MaybeAwaitable[AuthUser]]
    get_auth_user: Callable[[str], MaybeAwaitable[AuthUser | None]]
    login: Callable[[Response, Request, AuthUser], MaybeAwaitable[None]]
    logout: Callable[[Response, Request], MaybeAwaitable[None]]
    registration_allowed: Callable[[Request], MaybeAwaitable[bool]]
    render_login: Callable[[Request], MaybeAwaitable[Response]]
    render_register: RenderRegister
    after_register: Callable[[Request, AuthUser, PasskeyCredential], MaybeAwaitable[None]] = field(
        default=lambda _request, _user, _credential: None
    )
    after_login: Callable[[Request, AuthUser, PasskeyCredential], MaybeAwaitable[None]] = field(
        default=lambda _request, _user, _credential: None
    )


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
        cls,
        environ: Mapping[str, str] | None = None,
        *,
        prefix: str = "PASSKEY_",
    ) -> "PasskeyFastAPISettings":
        env = os.environ if environ is None else environ
        settings = cls(
            rp_id=_required_env(env, prefix, "RP_ID"),
            rp_name=_required_env(env, prefix, "RP_NAME"),
            origin=_required_env(env, prefix, "ORIGIN"),
            timeout_ms=_int_env(env, prefix, "TIMEOUT_MS", 60_000),
            challenge_ttl_seconds=_int_env(env, prefix, "CHALLENGE_TTL_SECONDS", 300),
            user_verification=_env(env, prefix, "USER_VERIFICATION", "required"),  # type: ignore[arg-type]
            paths=PasskeyPaths(
                login_page=_env(env, prefix, "LOGIN_PAGE", PasskeyPaths.login_page),
                register_page=_env(env, prefix, "REGISTER_PAGE", PasskeyPaths.register_page),
                logout=_env(env, prefix, "LOGOUT_PATH", PasskeyPaths.logout),
                login_options=_env(env, prefix, "LOGIN_OPTIONS_PATH", PasskeyPaths.login_options),
                login_verify=_env(env, prefix, "LOGIN_VERIFY_PATH", PasskeyPaths.login_verify),
                register_options=_env(env, prefix, "REGISTER_OPTIONS_PATH", PasskeyPaths.register_options),
                register_verify=_env(env, prefix, "REGISTER_VERIFY_PATH", PasskeyPaths.register_verify),
            ),
            cookies=PasskeyCookies(
                challenge=_env(env, prefix, "CHALLENGE_COOKIE", _env(env, prefix, "COOKIE_NAME", PasskeyCookies.challenge)),
                register_name=_env(env, prefix, "REGISTER_NAME_COOKIE", PasskeyCookies.register_name),
                path=_env(env, prefix, "COOKIE_PATH", PasskeyCookies.path),
                secure=_bool_env(env, prefix, "COOKIE_SECURE", True),
                httponly=_bool_env(env, prefix, "COOKIE_HTTPONLY", True),
                samesite=_env(env, prefix, "COOKIE_SAMESITE", PasskeyCookies.samesite),
            ),
        )
        settings.passkey_config()
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
        config=settings.passkey_config(),
        challenges=challenges,
        credentials=credentials,
    )
    return PasskeyAuthRouter(
        service=service,
        hooks=hooks,
        paths=settings.paths,
        cookies=settings.cookies,
    ).router


class PasskeyAuthRouter:
    def __init__(
        self,
        *,
        service: Any,
        hooks: PasskeyRouteHooks,
        paths: PasskeyPaths | None = None,
        cookies: PasskeyCookies | None = None,
    ) -> None:
        self.service = service
        self.hooks = hooks
        self.paths = paths or PasskeyPaths()
        self.cookies = cookies or PasskeyCookies()
        self.router = APIRouter()
        self._add_routes()

    def _add_routes(self) -> None:
        self.router.add_api_route(self.paths.login_page, self.login_page, methods=["GET"])
        self.router.add_api_route(self.paths.register_page, self.register_page, methods=["GET"])
        self.router.add_api_route(self.paths.logout, self.logout, methods=["POST"])
        self.router.add_api_route(self.paths.login_options, self.login_options, methods=["POST"])
        self.router.add_api_route(self.paths.login_verify, self.login_verify, methods=["POST"])
        self.router.add_api_route(self.paths.register_options, self.register_options, methods=["POST"])
        self.router.add_api_route(self.paths.register_verify, self.register_verify, methods=["POST"])

    async def login_page(self, request: Request) -> Response:
        return await _maybe_await(self.hooks.render_login(request))

    async def register_page(self, request: Request) -> Response:
        user = await _maybe_await(self.hooks.get_session_user(request))
        return await _maybe_await(self.hooks.render_register(request, bootstrap=user is None))

    async def login_options(self) -> Response:
        flow_id = self._new_flow_id()
        response = JSONResponse(self.service.begin_authentication(flow_id=flow_id))
        self._set_cookie(response, self.cookies.challenge, flow_id)
        return response

    async def login_verify(self, request: Request) -> Response:
        flow_id = self._challenge_cookie(request)
        credential = _without_legacy_user_handle(await _json_body(request))

        try:
            result = self.service.finish_authentication(
                flow_id=flow_id,
                credential=credential,
                require_user_handle=False,
            )
        except AUTH_ERRORS as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

        user = await _maybe_await(self.hooks.get_auth_user(result.user.user_id))
        if user is None:
            raise HTTPException(status_code=403, detail="authenticated user is not allowed")

        response = JSONResponse({"ok": True})
        self._delete_cookie(response, self.cookies.challenge)
        await _maybe_await(self.hooks.login(response, request, user))
        await _maybe_await(self.hooks.after_login(request, user, result.credential))
        return response

    async def register_options(self, request: Request) -> Response:
        if not await _maybe_await(self.hooks.registration_allowed(request)):
            raise HTTPException(status_code=403, detail="passkey registration is not allowed")

        session_user = await _maybe_await(self.hooks.get_session_user(request))
        user = session_user or await _maybe_await(
            self.hooks.make_registration_user(request, _registration_display_name(await _json_body(request)))
        )

        flow_id = self._new_flow_id()
        response = JSONResponse(self.service.begin_registration(flow_id=flow_id, user=user))
        self._set_cookie(response, self.cookies.challenge, flow_id)
        return response

    async def register_verify(self, request: Request) -> Response:
        flow_id = self._challenge_cookie(request)
        session_user = await _maybe_await(self.hooks.get_session_user(request))

        try:
            credential = self.service.finish_registration(flow_id=flow_id, credential=await _json_body(request))
        except AUTH_ERRORS as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

        user = session_user if session_user and session_user.user_id == credential.user_id else None
        if user is None:
            user = await _maybe_await(self.hooks.get_auth_user(credential.user_id))
        if user is None:
            raise HTTPException(status_code=403, detail="registered user is not allowed")

        response = JSONResponse({"ok": True})
        self._delete_cookie(response, self.cookies.challenge)
        self._delete_cookie(response, self.cookies.register_name)
        await _maybe_await(self.hooks.login(response, request, user))
        await _maybe_await(self.hooks.after_register(request, user, credential))
        return response

    async def logout(self, request: Request) -> Response:
        response = RedirectResponse(self.paths.login_page, status_code=303)
        await _maybe_await(self.hooks.logout(response, request))
        self._delete_cookie(response, self.cookies.challenge)
        self._delete_cookie(response, self.cookies.register_name)
        return response

    def _new_flow_id(self) -> str:
        return secrets.token_urlsafe(32)

    def _challenge_cookie(self, request: Request) -> str:
        flow_id = request.cookies.get(self.cookies.challenge)
        if not flow_id:
            raise HTTPException(status_code=400, detail="missing passkey challenge")
        return flow_id

    def _set_cookie(self, response: Response, key: str, value: str) -> None:
        response.set_cookie(
            key,
            value,
            max_age=self.service.config.challenge_ttl_seconds,
            path=self.cookies.path,
            secure=self.cookies.secure,
            httponly=self.cookies.httponly,
            samesite=self.cookies.samesite,
        )

    def _delete_cookie(self, response: Response, key: str) -> None:
        response.delete_cookie(
            key,
            path=self.cookies.path,
            secure=self.cookies.secure,
            httponly=self.cookies.httponly,
            samesite=self.cookies.samesite,
        )


async def _maybe_await(value: MaybeAwaitable[T]) -> T:
    if inspect.isawaitable(value):
        return await value
    return value


async def _json_body(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except ValueError:
        return {}
    if isinstance(body, dict):
        return body
    raise HTTPException(status_code=400, detail="JSON object body is required")


def _registration_display_name(body: Mapping[str, Any]) -> str:
    display_name = body.get("display_name") or body.get("displayName") or body.get("name")
    if not isinstance(display_name, str) or not display_name.strip():
        raise HTTPException(status_code=400, detail="display_name is required")
    return display_name.strip()


def _without_legacy_user_handle(credential: dict[str, Any]) -> dict[str, Any]:
    response = credential.get("response")
    if not isinstance(response, dict) or "userHandle" not in response:
        return credential
    copied = {**credential, "response": {**response}}
    copied["response"].pop("userHandle", None)
    return copied


def _env(env: Mapping[str, str], prefix: str, name: str, default: Any) -> Any:
    value = env.get(f"{prefix}{name}")
    if value is None or value == "":
        return default
    return value


def _required_env(env: Mapping[str, str], prefix: str, name: str) -> str:
    value = _env(env, prefix, name, None)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{prefix}{name} is required")
    return value.strip()


def _int_env(env: Mapping[str, str], prefix: str, name: str, default: int) -> int:
    value = _env(env, prefix, name, None)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as error:
        raise ValueError(f"{prefix}{name} must be an integer") from error


def _bool_env(env: Mapping[str, str], prefix: str, name: str, default: bool) -> bool:
    value = _env(env, prefix, name, None)
    if value is None:
        return default
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{prefix}{name} must be a boolean")


AUTH_ERRORS = (ChallengeNotFound, CredentialNotFound, UserHandleMismatch, ValueError, WebAuthnException)

__all__ = [
    "AuthUser",
    "PasskeyFastAPIHooks",
    "PasskeyFastAPISettings",
    "PasskeyAuthRouter",
    "PasskeyCookies",
    "PasskeyPaths",
    "PasskeyRouteHooks",
    "build_passkey_fastapi_plugin",
]
