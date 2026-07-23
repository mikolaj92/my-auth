from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from my_auth.passkeys import PasskeyService

from fastapi import APIRouter
from starlette.staticfiles import StaticFiles

from my_auth.fastapi import PasskeyAuthRouter, PasskeyRouteHooks

from .config import PasskeyUiConfig
from .static import passkey_ui_static_files
from .templates import PasskeyTemplateRenderer, build_template_environment


@dataclass(frozen=True, slots=True)
class PasskeyUiRouter:
    router: APIRouter
    static_mount_path: str
    static_files: StaticFiles

def create_passkey_ui_router(
    *,
    service: PasskeyService,
    hooks: PasskeyRouteHooks,
    config: PasskeyUiConfig | None = None,
) -> PasskeyUiRouter:
    resolved_config = config or PasskeyUiConfig()
    renderer = PasskeyTemplateRenderer(
        environment=build_template_environment(resolved_config),
        config=resolved_config,
    )
    wrapped_hooks = PasskeyRouteHooks(
        get_session_user=hooks.get_session_user,
        prepare_registration=hooks.prepare_registration,
        complete_registration=hooks.complete_registration,
        get_auth_user=hooks.get_auth_user,
        login=hooks.login,
        logout=hooks.logout,
        registration_allowed=hooks.registration_allowed,
        render_login=renderer.render_login,
        render_register=renderer.render_register,
        after_register=hooks.after_register,
        after_login=hooks.after_login,
    )
    auth_router = PasskeyAuthRouter(
        service=service,
        hooks=wrapped_hooks,
        paths=resolved_config.paths,
        cookies=resolved_config.cookies,
    )
    return PasskeyUiRouter(
        router=auth_router.router,
        static_mount_path=resolved_config.static_mount_path,
        static_files=passkey_ui_static_files(),
    )
