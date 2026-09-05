from __future__ import annotations

import inspect
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, TypeVar

from app_factory.jinja import configure_jinja_env
from fastapi import Request
from jinja2 import ChoiceLoader, Environment, PackageLoader, select_autoescape
from starlette.responses import HTMLResponse, Response

from my_auth.passkeys import PasskeyCredential

from .config import MaybeAwaitable, PasskeyUiConfig
from .i18n import ui_copy

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class PasskeyTemplateRenderer:
    environment: Environment
    config: PasskeyUiConfig

    async def render_login(self, request: Request) -> Response:
        return await self._render("login.html", request)

    async def render_register(self, request: Request) -> Response:
        return await self._render("register.html", request)

    async def render_credential_management(
        self, request: Request, *, credentials: Sequence[PasskeyCredential]
    ) -> Response:
        return await self._render(
            "credential_management.html",
            request,
            credentials=list(credentials),
        )

    async def render_capability_registration(
        self,
        request: Request,
        *,
        kind: Literal["invitation", "recovery"],
        capability: str | None,
    ) -> Response:
        return await self._render(
            "capability_registration.html",
            request,
            registration_kind=kind,
            capability=capability,
        )

    async def render_account_panel(self, request: Request) -> str:
        """Render the packaged registration UI for a signed-in account page."""
        return await self._render_content("account_panel.html", request)

    async def _render_content(
        self,
        template_name: str,
        request: Request,
        *,
        registration_kind: Literal["invitation", "recovery"] | None = None,
        capability: str | None = None,
        credentials: list[PasskeyCredential] | None = None,
    ) -> str:
        static_base = self.config.static_url_path.rstrip("/")
        csrf_token = await _maybe_await(self.config.csrf_token(request))
        lang = _resolve_locale(request, self.config)
        copy = dict(ui_copy(lang, default=self.config.default_locale))
        capability_valid = bool(capability and capability.strip())
        if registration_kind == "invitation":
            success_url = self.config.activation_success_url
        elif registration_kind == "recovery":
            success_url = self.config.recovery_success_url
        else:
            success_url = self.config.register_success_url
        platform_context = {
            "platform_user": None,
            "platform_identity_menu": (),
            "platform_show_register": False,
            **getattr(request.state, "app_factory_platform_context", {}),
        }
        platform_context.update(
            request=request,
            paths=self.config.paths,
            passkey_js_url=f"{static_base}/passkey-ui.js",
            passkey_css_url=f"{static_base}/passkey-ui.css",
            csrf_header_name=self.config.csrf_header_name,
            csrf_token=csrf_token,
            login_success_url=self.config.login_success_url,
            register_success_url=success_url,
            registration_kind=registration_kind,
            capability=capability if capability_valid else None,
            capability_valid=capability_valid,
            credentials=credentials or [],
            login_error_target_id=self.config.login_error_target_id,
            register_error_target_id=self.config.register_error_target_id,
            # Drive app-factory shell lang + flag dropdown selected state.
            lang=lang,
            platform_locale=lang,
            # Localized login/register chrome + client message map.
            t=copy,
            t_json=json.dumps(copy, ensure_ascii=False, separators=(",", ":")),
        )
        return self.environment.get_template(template_name).render(**platform_context)

    async def _render(
        self,
        template_name: str,
        request: Request,
        *,
        registration_kind: Literal["invitation", "recovery"] | None = None,
        capability: str | None = None,
        credentials: list[PasskeyCredential] | None = None,
    ) -> Response:
        content = await self._render_content(
            template_name,
            request,
            registration_kind=registration_kind,
            capability=capability,
            credentials=credentials,
        )
        lang = _resolve_locale(request, self.config)
        response = HTMLResponse(content)
        cookie_name = self.config.locale_cookie_name
        if cookie_name and lang in self.config.supported_locales:
            response.set_cookie(
                cookie_name,
                lang,
                httponly=False,
                samesite="lax",
                path="/",
            )
        return response


def _resolve_locale(request: Request, config: PasskeyUiConfig) -> str:
    """Prefer ?lang=, then host cookie, then configured default."""
    param = config.locale_query_param or "lang"
    query = request.query_params.get(param)
    if query in config.supported_locales:
        return query
    cookie_name = config.locale_cookie_name
    if cookie_name:
        cookie = request.cookies.get(cookie_name)
        if cookie in config.supported_locales:
            return cookie
    if config.default_locale in config.supported_locales:
        return config.default_locale
    return config.supported_locales[0] if config.supported_locales else "en"


def build_template_environment(_config: PasskeyUiConfig) -> Environment:
    environment = Environment(
        loader=ChoiceLoader(
            [
                PackageLoader("my_auth.fastapi_htmx", "templates"),
                PackageLoader("app_factory", "templates"),
            ]
        ),
        autoescape=select_autoescape(("html", "xml")),
    )
    configure_jinja_env(environment)
    return environment


async def _maybe_await(value: MaybeAwaitable[T]) -> T:
    if inspect.isawaitable(value):
        return await value
    return value
