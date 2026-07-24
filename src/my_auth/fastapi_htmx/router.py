from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, FastAPI
from starlette.staticfiles import StaticFiles

from app_factory.fastapi import AppFactoryUi, AppFactoryUiConflict, install_app_factory_ui
from my_auth.fastapi import PasskeyAuthRouter, PasskeyRouteHooks

from .config import PasskeyUiConfig
from .static import _passkey_ui_static_files
from .templates import PasskeyTemplateRenderer, build_template_environment

if TYPE_CHECKING:
    from jinja2 import Environment


class PasskeyUiConflict(ValueError):
    """The application already has a different my-auth UI installation."""


@dataclass(frozen=True, slots=True)
class PasskeyUi:
    router: APIRouter
    static_mount_path: str
    static_files: StaticFiles
    platform: AppFactoryUi
    config: PasskeyUiConfig


def install_passkey_ui(
    app: FastAPI,
    *,
    platform: AppFactoryUi,
    service: Any,
    hooks: PasskeyRouteHooks,
    config: PasskeyUiConfig | None = None,
) -> PasskeyUi:
    resolved_config = config or PasskeyUiConfig()
    existing = getattr(app.state, "my_auth_passkey_ui", None)
    if existing is not None:
        if existing.platform != platform or existing.config != resolved_config:
            raise PasskeyUiConflict("my-auth passkey UI is already installed with different configuration")
        return existing

    installed_platform = getattr(app.state, "app_factory_ui", None)
    if installed_platform != platform:
        raise AppFactoryUiConflict("platform must be installed on this application before my-auth UI")

    environment = build_template_environment(resolved_config)
    install_app_factory_ui(
        app,
        environments=[environment],
        static_path=platform.static_path,
        mount_name=platform.mount_name,
    )
    renderer = PasskeyTemplateRenderer(environment=environment, config=resolved_config)
    wrapped_hooks = PasskeyRouteHooks(
        get_session_user=hooks.get_session_user,
        make_registration_user=hooks.make_registration_user,
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
    static_files = _passkey_ui_static_files()
    app.mount(resolved_config.static_mount_path, static_files, name="my-auth-passkey-ui")
    result = PasskeyUi(
        router=auth_router.router,
        static_mount_path=resolved_config.static_mount_path,
        static_files=static_files,
        platform=platform,
        config=resolved_config,
    )
    app.include_router(result.router)
    app.state.my_auth_passkey_ui = result
    return result
