from __future__ import annotations

import dataclasses
import importlib
import inspect
import re
import subprocess
import sys
import textwrap
from importlib.resources import files
from pathlib import Path
from types import ModuleType

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jinja2 import DictLoader
from starlette.staticfiles import StaticFiles

from app_factory.fastapi import install_app_factory_ui
from my_auth.fastapi import PasskeyAuthRouter, PasskeyCookies, PasskeyPaths
from test_fastapi_adapter import FakePasskeyService, HookRecorder, hooks_for


EXPECTED_PUBLIC_API = {
    "PasskeyUi",
    "PasskeyUiConfig",
    "PasskeyUiConflict",
    "install_passkey_ui",
}
EXPECTED_CONFIG_FIELDS = [
    "paths",
    "cookies",
    "static_mount_path",
    "static_url_path",
    "passkey_js_url",
    "template_override_directory",
    "template_loader",
    "csrf_header_name",
    "csrf_token",
    "login_success_url",
    "register_success_url",
    "login_error_target_id",
    "register_error_target_id",
]
EXPECTED_RESOURCE_PATHS = [
    "templates/login.html",
    "templates/register.html",
    "templates/_login_panel.html",
    "templates/_register_panel.html",
    "templates/_passkey_status.html",
    "static/passkey-ui.js",
    "static/passkey-ui.css",
]
REPO_ROOT = Path(__file__).resolve().parents[1]


def _import_ui_adapter() -> ModuleType:
    try:
        return importlib.import_module("my_auth.fastapi_htmx")
    except ModuleNotFoundError as error:
        if error.name == "my_auth.fastapi_htmx":
            pytest.fail(
                "planned RED: my_auth.fastapi_htmx is missing; implement the explicit "
                "FastAPI HTMX UI adapter module with the Phase 1 public contract",
                pytrace=False,
            )
        raise


def _client_for(module: ModuleType, config=None):  # noqa: ANN001, ANN201
    service = FakePasskeyService()
    recorder = HookRecorder()
    app = FastAPI()
    platform = install_app_factory_ui(app, environments=[], static_path="/static/platform", mount_name="platform")
    ui = module.install_passkey_ui(app, platform=platform, service=service, hooks=hooks_for(recorder), config=config)
    return TestClient(app), service, recorder, ui


def _resource_text(relative_path: str) -> str:
    return files("my_auth.fastapi_htmx").joinpath(*relative_path.split("/")).read_text()


def _route_pairs(router) -> list[tuple[str, str]]:  # noqa: ANN001
    pairs: list[tuple[str, str]] = []
    for route in router.routes:
        for method in getattr(route, "methods", set()):
            if method != "HEAD":
                pairs.append((method, route.path))
    return sorted(pairs)


def test_root_import_does_not_load_ui_or_optional_framework_modules() -> None:
    # Given: a fresh Python subprocess with no my_auth modules imported.
    code = textwrap.dedent(
        """
        import sys
        import my_auth

        forbidden = {"fastapi", "jinja2", "my_auth.fastapi", "my_auth.fastapi_htmx"}
        loaded = sorted(forbidden & set(sys.modules))
        print("loaded=" + repr(loaded))
        raise SystemExit(1 if loaded else 0)
        """
    )

    # When: only the package root is imported.
    result = subprocess.run([sys.executable, "-c", code], text=True, capture_output=True, check=False)

    # Then: optional FastAPI/Jinja/UI boundaries stay unloaded.
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "loaded=[]"


def test_fastapi_htmx_is_an_explicit_ui_boundary_import() -> None:
    # Given: the root import is already proven clean in-process.
    code = textwrap.dedent(
        """
        import importlib
        import sys
        import my_auth

        before = "my_auth.fastapi_htmx" in sys.modules
        importlib.import_module("my_auth.fastapi_htmx")
        after = "my_auth.fastapi_htmx" in sys.modules
        print(f"before={before} after={after}")
        """
    )

    # When: the UI adapter is imported explicitly.
    result = subprocess.run([sys.executable, "-c", code], text=True, capture_output=True, check=False)

    # Then: that explicit module is the only UI adapter boundary.
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "before=False after=True"


def test_public_api_exports_exact_passkey_ui_contract() -> None:
    # Given: the explicit UI adapter module exists.
    module = _import_ui_adapter()

    # When: callers inspect the public API surface.
    exported = set(module.__all__)

    # Then: only the planned adapter symbols are public, with no PasskeyUiHooks seam.
    assert exported == EXPECTED_PUBLIC_API
    for name in EXPECTED_PUBLIC_API:
        assert hasattr(module, name)
    assert not hasattr(module, "PasskeyUiHooks")


def test_config_and_installation_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _import_ui_adapter()
    config_type = module.PasskeyUiConfig
    config = config_type()
    assert dataclasses.is_dataclass(config_type)
    assert config_type.__dataclass_params__.frozen is True
    assert set(config_type.__slots__) == set(EXPECTED_CONFIG_FIELDS)
    assert [field.name for field in dataclasses.fields(config_type)] == EXPECTED_CONFIG_FIELDS
    assert config.paths == PasskeyPaths()
    assert config.cookies == PasskeyCookies()
    assert config.passkey_js_url == "/auth/ui/static/passkey-ui.js"
    assert config.template_override_directory is None
    assert config.template_loader is None
    assert config.csrf_header_name == "X-CSRF-Token"
    assert config.csrf_token(None) is None
    assert list(inspect.signature(module.install_passkey_ui).parameters) == ["app", "platform", "service", "hooks", "config"]


def test_installation_mounts_router_and_platform_once(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _import_ui_adapter()
    config = module.PasskeyUiConfig(paths=PasskeyPaths(login_page="/auth/login", register_page="/auth/register"))
    client, service, _, ui = _client_for(module, config)
    assert dataclasses.is_dataclass(ui)
    assert isinstance(ui.static_files, StaticFiles)
    assert ui.static_mount_path == "/auth/ui/static"
    assert ui.platform.static_path == "/static/platform"
    assert _route_pairs(ui.router) == sorted([
        ("GET", "/auth/login"), ("GET", "/auth/register"), ("POST", "/logout"),
        ("POST", "/api/auth/login/options"), ("POST", "/api/auth/login/verify"),
        ("POST", "/api/auth/register/options"), ("POST", "/api/auth/register/verify"),
    ])
    assert client.get("/auth/login").status_code == 200
    assert service is not None


def test_template_and_static_package_resources_match_js_contract() -> None:
    _import_ui_adapter()
    base = files("my_auth.fastapi_htmx")
    missing = [path for path in EXPECTED_RESOURCE_PATHS if not base.joinpath(*path.split("/")).is_file()]
    ui_js = _resource_text("static/passkey-ui.js")
    assert missing == []
    assert "fetchOptions" in ui_js
    assert "headers" in ui_js
    assert "registerPasskey" in ui_js
    assert "loginPasskey" in ui_js


def test_template_loader_override_contract(tmp_path: Path) -> None:
    # Given: hosts can supply either a complete loader or an override directory, but not both.
    module = _import_ui_adapter()
    config_type = module.PasskeyUiConfig
    override_loader = DictLoader(
        {
            "login.html": "login override {{ paths.login_options }} {{ csrf_header_name }}",
            "register.html": "register override {{ bootstrap }} {{ register_error_target_id }}",
        }
    )
    override_directory = tmp_path / "templates"
    override_directory.mkdir()
    override_directory.joinpath("login.html").write_text("directory override {{ passkey_js_url }}")

    # When: a custom loader is supplied.
    client, _, _, _ = _client_for(module, config_type(template_loader=override_loader))

    # Then: that loader is used directly, and ambiguous loader configuration is rejected.
    login = client.get("/login")
    register = client.get("/register")
    assert login.status_code == 200
    assert register.status_code == 200
    assert "login override /api/auth/login/options X-CSRF-Token" in login.text
    assert "register override True passkey-register-status" in register.text
    with pytest.raises(ValueError):
        config_type(template_loader=override_loader, template_override_directory=override_directory)

    directory_client, _, _, _ = _client_for(module, config_type(template_override_directory=override_directory))
    directory_login = directory_client.get("/login")
    directory_register = directory_client.get("/register")
    assert "directory override /auth/ui/static/passkey-ui.js" in directory_login.text
    assert "passkey-register-status" in directory_register.text


def test_login_and_register_pages_render_html_htmx_csrf_and_prefix_safe_static_url() -> None:
    # Given: a host configures custom UI paths, static URLs, CSRF metadata, and stable status targets.
    module = _import_ui_adapter()
    config = module.PasskeyUiConfig(
        paths=PasskeyPaths(login_page="/auth/login", register_page="/auth/register"),
        static_mount_path="/assets/passkeys",
        static_url_path="/assets/passkeys",
        passkey_js_url="/assets/passkeys/passkey-ui.js",
        csrf_header_name="X-Test-CSRF",
        csrf_token=lambda _request: "csrf-token-123",
        login_error_target_id="custom-login-status",
        register_error_target_id="custom-register-status",
    )
    client, _, _, _ = _client_for(module, config)

    # When: the full-page login/register endpoints and mounted static asset are requested.
    login = client.get("/auth/login")
    register = client.get("/auth/register")
    static_js = client.get("/assets/passkeys/passkey-ui.js")

    # Then: pages are HTML, HTMX/Basecoat-oriented, CSRF-aware, fallback-friendly, and prefix-safe.
    assert login.status_code == 200
    assert register.status_code == 200
    assert static_js.status_code == 200
    assert login.headers["content-type"].startswith("text/html")
    assert register.headers["content-type"].startswith("text/html")
    combined_html = login.text + register.text
    assert "custom-login-status" in login.text
    assert "custom-register-status" in register.text
    assert "hx-" in combined_html
    assert "/assets/passkeys/passkey-ui.js" in combined_html
    assert "X-Test-CSRF" in combined_html
    assert "csrf-token-123" in combined_html
    assert "passkey-ui.css" in login.text


def test_existing_api_endpoints_stay_json_and_challenge_cookies_remain_adapter_owned() -> None:
    # Given: the UI adapter wraps the existing JSON passkey routes.
    module = _import_ui_adapter()
    client, _, _, _ = _client_for(module)

    # When: JSON WebAuthn endpoints succeed and fail through the UI router.
    options = client.post("/api/auth/login/options")
    missing_cookie = client.post("/api/auth/login/verify", json={"id": "credential"})

    # Then: API responses remain JSON and only WebAuthn challenge cookies are adapter-owned.
    assert options.status_code == 200
    assert options.headers["content-type"].startswith("application/json")
    assert options.json()["challenge"] == "login-challenge"
    assert missing_cookie.status_code == 400
    assert missing_cookie.headers["content-type"].startswith("application/json")
    assert missing_cookie.json()["detail"] == "missing passkey challenge"
    set_cookies = options.headers.get_list("set-cookie")
    assert set_cookies
    assert all(cookie.startswith("passkey_challenge=") for cookie in set_cookies)
