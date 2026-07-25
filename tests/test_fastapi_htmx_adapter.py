from __future__ import annotations

import dataclasses
import importlib
import subprocess
import sys
import textwrap
from importlib.resources import files
from pathlib import Path

import pytest
from app_factory.fastapi import (
    AppFactoryUi,
    AppFactoryUiConflict,
    install_app_factory_ui,
)
from fastapi import FastAPI, Request, Response
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from my_auth import (
    MemoryChallengeStore,
    MemoryCredentialStore,
    PasskeyConfig,
    PasskeyService,
    PasskeyUser,
    VerifiedRegistration,
)
from my_auth.fastapi import PasskeyRouteHooks
from my_auth.fastapi_htmx import (
    PasskeyUi,
    PasskeyUiConfig,
    PasskeyUiConflict,
    install_passkey_ui,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_root_import_keeps_optional_ui_boundary_unloaded() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            textwrap.dedent(
                """
                import sys
                import my_auth
                forbidden = {"fastapi", "jinja2", "app_factory", "my_auth.fastapi_htmx"}
                assert not forbidden & set(sys.modules)
                """
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _hooks() -> PasskeyRouteHooks:
    user = PasskeyUser("u", b"handle", "name")

    async def session(_request: Request):
        return None

    async def prepare(_request: Request, _display_name: str):
        return user

    async def complete(_request: Request, result: VerifiedRegistration):
        return result.user

    async def auth(_user_id: str):
        return user

    async def login(_response: Response, _request: Request, _user: PasskeyUser):
        return None

    async def logout(_response: Response, _request: Request):
        return None

    async def policy(_request: Request):
        return True

    async def render_login(_request: Request):
        raise AssertionError("installer must replace render_login")

    async def render_register(request: Request, *, bootstrap: bool):
        del request, bootstrap
        raise AssertionError("installer must replace render_register")

    return PasskeyRouteHooks(
        get_session_user=session,
        prepare_registration=prepare,
        complete_registration=complete,
        get_auth_user=auth,
        login=login,
        logout=logout,
        registration_allowed=policy,
        render_login=render_login,
        render_register=render_register,
    )


def _service() -> PasskeyService:
    return PasskeyService(
        config=PasskeyConfig(
            rp_id="localhost", rp_name="Demo", origin="http://localhost"
        ),
        challenges=MemoryChallengeStore(),
        credentials=MemoryCredentialStore(),
    )


def _app() -> tuple[FastAPI, AppFactoryUi, PasskeyUi]:
    app = FastAPI()
    platform = AppFactoryUi(
        "/static/platform", "app-factory-platform", "/static/platform"
    )
    install_app_factory_ui(
        app,
        environments=[],
        static_path=platform.static_path,
        mount_name=platform.mount_name,
    )
    ui = install_passkey_ui(app, platform=platform, service=_service(), hooks=_hooks())
    return app, platform, ui


def test_public_api_has_only_installer_contract() -> None:
    module = importlib.import_module("my_auth.fastapi_htmx")
    assert set(module.__all__) == {
        "PasskeyUi",
        "PasskeyUiConfig",
        "PasskeyUiConflict",
        "install_passkey_ui",
    }
    assert not hasattr(module, "create_passkey_ui_router")
    assert not hasattr(module, "PasskeyUiRouter")
    params = getattr(PasskeyUi, "__dataclass_params__", None)
    assert dataclasses.is_dataclass(PasskeyUi) and getattr(params, "frozen", False)


def test_installer_is_idempotent_and_rejects_different_setup() -> None:
    app, platform, first = _app()
    second = install_passkey_ui(
        app, platform=platform, service=_service(), hooks=_hooks()
    )
    assert second is first
    with pytest.raises(PasskeyUiConflict):
        install_passkey_ui(
            app,
            platform=platform,
            service=_service(),
            hooks=_hooks(),
            config=PasskeyUiConfig(static_mount_path="/other/static"),
        )
    with pytest.raises(AppFactoryUiConflict):
        install_passkey_ui(
            FastAPI(),
            platform=platform,
            service=_service(),
            hooks=_hooks(),
        )


def test_installer_rejects_static_mount_overlap() -> None:
    app = FastAPI()
    platform = AppFactoryUi(
        "/static/platform", "app-factory-platform", "/static/platform"
    )
    install_app_factory_ui(
        app,
        environments=[],
        static_path=platform.static_path,
        mount_name=platform.mount_name,
    )

    for path in ("/static/platform", "/static/platform/auth", "/static"):
        with pytest.raises(PasskeyUiConflict, match="overlaps existing mount"):
            install_passkey_ui(
                app,
                platform=platform,
                service=_service(),
                hooks=_hooks(),
                config=PasskeyUiConfig(
                    static_mount_path=path,
                    static_url_path=path,
                ),
            )


def test_testclient_smoke_pages_and_package_js() -> None:
    app, _, ui = _app()
    client = TestClient(app)
    login = client.get("/login")
    register = client.get("/register")
    javascript = client.get(f"{ui.static_mount_path}/passkey-ui.js")
    package_javascript = client.get(f"{ui.static_mount_path}/passkey.js")
    assert (
        login.status_code
        == register.status_code
        == javascript.status_code
        == package_javascript.status_code
        == 200
    )
    assert login.headers["content-type"].startswith("text/html")
    assert register.headers["content-type"].startswith("text/html")
    assert "app-shell" in login.text
    assert "app-shell" in register.text
    assert f"{ui.static_mount_path}/passkey-ui.js" in login.text
    assert f"{ui.static_mount_path}/passkey-ui.js" in register.text
    assert 'from "./passkey.js"' in javascript.text
    assert "export async function loginPasskey" in package_javascript.text
    assert "export async function registerPasskey" in package_javascript.text
    assert (
        files("my_auth").joinpath("static/passkey.js").read_text()
        == package_javascript.text
    )


def test_adapter_keeps_one_json_router_and_host_owns_hooks() -> None:
    app, _, ui = _app()
    paths: list[tuple[str, tuple[str, ...]]] = [
        (route.path, tuple(sorted(route.methods or ())))
        for route in ui.router.routes
        if isinstance(route, APIRoute)
    ]
    assert paths.count(("/login", ("GET",))) == 1
    assert paths.count(("/register", ("GET",))) == 1
    assert any(path == "/api/auth/login/options" for path, _ in paths)
    assert any(path == "/api/auth/register/options" for path, _ in paths)
    assert app.state.my_auth_passkey_ui is ui


def test_no_legacy_ui_symbols_or_duplicate_static_helper_source() -> None:
    router_source = (REPO_ROOT / "src/my_auth/fastapi_htmx/router.py").read_text()
    package_source = (REPO_ROOT / "src/my_auth/fastapi_htmx/__init__.py").read_text()
    assert "create_passkey_ui_router" not in router_source + package_source
    assert "def passkey_ui_static_files" not in router_source + package_source
    assert (REPO_ROOT / "src/my_auth/fastapi_htmx/static/passkey.js").is_file()
