from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, FastAPI
from starlette.staticfiles import StaticFiles

from app_factory.fastapi import (
    AppFactoryUi,
    AppFactoryUiConflict,
    install_app_factory_ui,
)
from my_auth.fastapi import PasskeyAuthRouter, PasskeyRouteHooks

from .config import PasskeyUiConfig
from .static import _passkey_ui_static_files
from .templates import PasskeyTemplateRenderer, build_template_environment


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
            raise PasskeyUiConflict(
                "my-auth passkey UI is already installed with different configuration"
            )
        return existing

    installed_platform = getattr(app.state, "app_factory_ui", None)
    if installed_platform != platform:
        raise AppFactoryUiConflict(
            "platform must be installed on this application before my-auth UI"
        )

    static_mount_path = resolved_config.static_mount_path.rstrip("/")
    for route in app.routes:
        existing_path = getattr(route, "path", "").rstrip("/")
        if existing_path and (
            static_mount_path == existing_path
            or static_mount_path.startswith(f"{existing_path}/")
            or existing_path.startswith(f"{static_mount_path}/")
        ):
            raise PasskeyUiConflict(
                f"static mount path {static_mount_path!r} overlaps existing mount "
                f"{existing_path!r}"
            )
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
    static_files = _passkey_ui_static_files()
    app.mount(
        resolved_config.static_mount_path, static_files, name="my-auth-passkey-ui"
    )
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
