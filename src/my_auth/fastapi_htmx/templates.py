from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import TypeVar

from fastapi import Request
from jinja2 import BaseLoader, ChoiceLoader, Environment, FileSystemLoader, PackageLoader, select_autoescape
from starlette.responses import HTMLResponse, Response

from .config import MaybeAwaitable, PasskeyUiConfig, TemplateLoaderConflictError

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class PasskeyTemplateRenderer:
    environment: Environment
    config: PasskeyUiConfig

    async def render_login(self, request: Request) -> Response:
        return await self._render("login.html", request, bootstrap=False)

    async def render_register(self, request: Request, *, bootstrap: bool) -> Response:
        return await self._render("register.html", request, bootstrap=bootstrap)

    async def _render(self, template_name: str, request: Request, *, bootstrap: bool) -> Response:
        static_base = self.config.static_url_path.rstrip("/")
        csrf_token = await _maybe_await(self.config.csrf_token(request))
        content = self.environment.get_template(template_name).render(
            request=request,
            paths=self.config.paths,
            bootstrap=bootstrap,
            passkey_js_url=self.config.passkey_js_url,
            passkey_css_url=f"{static_base}/passkey-ui.css" if static_base else "/passkey-ui.css",
            csrf_header_name=self.config.csrf_header_name,
            csrf_token=csrf_token,
            login_success_url=self.config.login_success_url,
            register_success_url=self.config.register_success_url,
            login_error_target_id=self.config.login_error_target_id,
            register_error_target_id=self.config.register_error_target_id,
        )
        return HTMLResponse(content)


def build_template_environment(config: PasskeyUiConfig) -> Environment:
    return Environment(
        loader=_template_loader(config),
        autoescape=select_autoescape(("html", "xml")),
    )


def _template_loader(config: PasskeyUiConfig) -> BaseLoader:
    packaged_loader = PackageLoader("my_auth.fastapi_htmx", "templates")
    if config.template_loader is not None and config.template_override_directory is not None:
        raise TemplateLoaderConflictError()
    if config.template_loader is not None:
        return config.template_loader
    if config.template_override_directory is not None:
        return ChoiceLoader([FileSystemLoader(config.template_override_directory), packaged_loader])
    return packaged_loader


async def _maybe_await(value: MaybeAwaitable[T]) -> T:
    if inspect.isawaitable(value):
        return await value
    return value
