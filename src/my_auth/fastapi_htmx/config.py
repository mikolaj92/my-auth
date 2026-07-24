from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TypeVar

from fastapi import Request

from my_auth.fastapi import PasskeyCookies, PasskeyPaths

T = TypeVar("T")
MaybeAwaitable = T | Awaitable[T]


def no_csrf_token(_request: Request) -> str | None:
    return None


@dataclass(frozen=True, slots=True)
class PasskeyUiConfig:
    """Host-owned route, cookie, CSRF, and redirect configuration."""

    paths: PasskeyPaths = PasskeyPaths()
    cookies: PasskeyCookies = PasskeyCookies()
    static_mount_path: str = "/auth/ui/static"
    static_url_path: str = "/auth/ui/static"
    csrf_header_name: str = "X-CSRF-Token"
    csrf_token: Callable[[Request], MaybeAwaitable[str | None]] = no_csrf_token
    login_success_url: str | None = None
    register_success_url: str | None = None
    login_error_target_id: str = "passkey-login-status"
    register_error_target_id: str = "passkey-register-status"

    def __post_init__(self) -> None:
        for field_name in ("static_mount_path", "static_url_path"):
            value = getattr(self, field_name)
            if not value.startswith("/") or value == "/":
                raise ValueError(f"{field_name} must be an absolute non-root path")
