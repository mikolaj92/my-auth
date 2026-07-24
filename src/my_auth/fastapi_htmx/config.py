from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

from fastapi import Request
from jinja2 import BaseLoader

from my_auth.fastapi import PasskeyCookies, PasskeyPaths

T = TypeVar("T")
MaybeAwaitable = T | Awaitable[T]


def no_csrf_token(_request: Request) -> str | None:
    return None


@dataclass(frozen=True, slots=True)
class TemplateLoaderConflictError(ValueError):
    def __str__(self) -> str:
        return "template_loader and template_override_directory are mutually exclusive"


@dataclass(frozen=True, slots=True)
class PasskeyUiConfig:
    """Host-owned route, cookie, CSRF, and redirect configuration."""

    paths: PasskeyPaths = PasskeyPaths()
    cookies: PasskeyCookies = PasskeyCookies()
    static_mount_path: str = "/auth/ui/static"
    static_url_path: str = "/auth/ui/static"
    passkey_js_url: str = "/auth/ui/static/passkey-ui.js"
    template_override_directory: Path | None = None
    template_loader: BaseLoader | None = None
    csrf_header_name: str = "X-CSRF-Token"
    csrf_token: Callable[[Request], MaybeAwaitable[str | None]] = no_csrf_token
    login_success_url: str | None = None
    register_success_url: str | None = None
    login_error_target_id: str = "passkey-login-status"
    register_error_target_id: str = "passkey-register-status"

    def __post_init__(self) -> None:
        if self.template_loader is not None and self.template_override_directory is not None:
            raise TemplateLoaderConflictError()
        for field_name in ("static_mount_path", "static_url_path"):
            value = getattr(self, field_name)
            if not value.startswith("/") or value == "/":
                raise ValueError(f"{field_name} must be an absolute non-root path")
