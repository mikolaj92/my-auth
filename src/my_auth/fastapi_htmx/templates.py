from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import TypeVar

from app_factory.jinja import configure_jinja_env
from fastapi import Request
from jinja2 import ChoiceLoader, Environment, PackageLoader, select_autoescape
from starlette.responses import HTMLResponse, Response

from .config import MaybeAwaitable, PasskeyUiConfig

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class PasskeyTemplateRenderer:
    environment: Environment
    config: PasskeyUiConfig

    async def render_login(self, request: Request) -> Response:
        return await self._render("login.html", request, bootstrap=False)

    async def render_register(self, request: Request, *, bootstrap: bool) -> Response:
        return await self._render("register.html", request, bootstrap=bootstrap)

    async def _render(
        self, template_name: str, request: Request, *, bootstrap: bool
    ) -> Response:
        static_base = self.config.static_url_path.rstrip("/")
        csrf_token = await _maybe_await(self.config.csrf_token(request))
        lang = _resolve_locale(request, self.config)
        content = self.environment.get_template(template_name).render(
            request=request,
            paths=self.config.paths,
            bootstrap=bootstrap,
            passkey_js_url=f"{static_base}/passkey-ui.js",
            passkey_css_url=f"{static_base}/passkey-ui.css",
            csrf_header_name=self.config.csrf_header_name,
            csrf_token=csrf_token,
            login_success_url=self.config.login_success_url,
            register_success_url=self.config.register_success_url,
            login_error_target_id=self.config.login_error_target_id,
            register_error_target_id=self.config.register_error_target_id,
            # Drive app-factory shell lang + flag dropdown selected state.
            lang=lang,
            platform_locale=lang,
        )
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
