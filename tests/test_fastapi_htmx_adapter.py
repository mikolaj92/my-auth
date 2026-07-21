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

from my_auth.fastapi import PasskeyAuthRouter, PasskeyCookies, PasskeyPaths
from test_fastapi_adapter import FakePasskeyService, HookRecorder, hooks_for


EXPECTED_PUBLIC_API = {
    "PasskeyUiConfig",
    "PasskeyUiRouter",
    "create_passkey_ui_router",
    "passkey_ui_static_files",
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
    "templates/base.html",
    "templates/login.html",
    "templates/register.html",
    "templates/_login_panel.html",
    "templates/_register_panel.html",
    "templates/_passkey_status.html",
    "static/passkey.js",
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
    ui_router = module.create_passkey_ui_router(service=service, hooks=hooks_for(recorder), config=config)
    app = FastAPI()
    app.include_router(ui_router.router)
    app.mount(ui_router.static_mount_path, ui_router.static_files, name="my_auth_fastapi_htmx_static")
    return TestClient(app), service, recorder, ui_router


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


def test_config_and_factory_signature_match_planned_contract() -> None:
    # Given: hosts configure the UI adapter through a frozen dataclass and factory.
    module = _import_ui_adapter()

    # When: the config and factory contract are inspected.
    config_type = module.PasskeyUiConfig
    signature = inspect.signature(module.create_passkey_ui_router)
    config = config_type()

    # Then: the dataclass shape, defaults, and keyword-only factory match the plan.
    assert dataclasses.is_dataclass(config_type)
    assert config_type.__dataclass_params__.frozen is True
    assert set(config_type.__slots__) == set(EXPECTED_CONFIG_FIELDS)
    assert [field.name for field in dataclasses.fields(config_type)] == EXPECTED_CONFIG_FIELDS
    assert config.paths == PasskeyPaths()
    assert config.cookies == PasskeyCookies()
    assert config.static_mount_path == "/auth/ui/static"
    assert config.static_url_path == "/auth/ui/static"
    assert config.passkey_js_url == "/auth/ui/static/passkey-ui.js"
    assert config.template_override_directory is None
    assert config.template_loader is None
    assert config.csrf_header_name == "X-CSRF-Token"
    assert config.csrf_token(None) is None
    assert config.login_success_url is None
    assert config.register_success_url is None
    assert config.login_error_target_id == "passkey-login-status"
    assert config.register_error_target_id == "passkey-register-status"
    assert list(signature.parameters) == ["service", "hooks", "config"]
    assert all(parameter.kind is inspect.Parameter.KEYWORD_ONLY for parameter in signature.parameters.values())
    assert signature.parameters["config"].default is None
    assert "Any" in inspect.formatannotation(signature.parameters["service"].annotation)
    assert "PasskeyRouteHooks" in inspect.formatannotation(signature.parameters["hooks"].annotation)
    assert "PasskeyUiConfig" in inspect.formatannotation(signature.parameters["config"].annotation)
    assert "PasskeyUiRouter" in inspect.formatannotation(signature.return_annotation)


def test_factory_returns_mountable_router_and_wraps_exactly_one_passkey_router(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given: a host service, existing FastAPI hooks, and custom path/cookie config.
    module = _import_ui_adapter()
    config = module.PasskeyUiConfig(
        paths=PasskeyPaths(login_page="/auth/login", register_page="/auth/register"),
        cookies=PasskeyCookies(challenge="custom_challenge", register_name="custom_register_name"),
    )
    calls = []
    original_init = PasskeyAuthRouter.__init__

    def counted_init(self, *, service, hooks, paths=None, cookies=None) -> None:  # noqa: ANN001
        calls.append((service, hooks, paths, cookies))
        original_init(self, service=service, hooks=hooks, paths=paths, cookies=cookies)

    monkeypatch.setattr(PasskeyAuthRouter, "__init__", counted_init)

    # When: the UI router is created.
    client, service, _, ui_router = _client_for(module, config)

    # Then: it returns the planned mount object and delegates to one existing PasskeyAuthRouter.
    assert dataclasses.is_dataclass(ui_router)
    assert type(ui_router).__dataclass_params__.frozen is True
    assert isinstance(ui_router.static_files, StaticFiles)
    assert ui_router.static_mount_path == "/auth/ui/static"
    assert len(calls) == 1
    assert calls[0][0] is service
    assert calls[0][2] == config.paths
    assert calls[0][3] == config.cookies
    assert _route_pairs(ui_router.router) == sorted(
        [
            ("GET", "/auth/login"),
            ("GET", "/auth/register"),
            ("POST", "/logout"),
            ("POST", "/api/auth/login/options"),
            ("POST", "/api/auth/login/verify"),
            ("POST", "/api/auth/register/options"),
            ("POST", "/api/auth/register/verify"),
        ]
    )
    assert client.get("/auth/login").status_code == 200


def test_template_and_static_package_resources_match_js_contract() -> None:
    # Given: the UI adapter ships real package resources.
    _import_ui_adapter()
    base = files("my_auth.fastapi_htmx")

    # When: callers inspect templates and static files through importlib.resources.
    missing = [path for path in EXPECTED_RESOURCE_PATHS if not base.joinpath(*path.split("/")).is_file()]
    ui_js = _resource_text("static/passkey-ui.js")
    ui_passkey_js = _resource_text("static/passkey.js")
    core_passkey_js = (REPO_ROOT / "src/my_auth/static/passkey.js").read_text()

    # Then: assets are packaged, UI JS imports the local passkey module, and passkey.js preserves core exports.
    assert missing == []
    assert re.search(r"[\"']\./passkey\.js[\"']", ui_js)
    assert "fetchOptions" in ui_js
    assert "headers" in ui_js
    if ui_passkey_js != core_passkey_js:
        assert re.search(r"intentional wrapper|re-export", ui_passkey_js, re.IGNORECASE)
        assert "loginPasskey" in ui_passkey_js
        assert "registerPasskey" in ui_passkey_js
        assert "passkeyEncoding" in ui_passkey_js


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
    assert re.search(r"unsupported|not support|PublicKeyCredential|WebAuthn", combined_html, re.IGNORECASE)
    # Shared app-factory chrome (same stack as host apps)
    assert "basecoat-factory" in login.text
    assert "basecoat-factory" in register.text
    assert "passkey-ui.css" in login.text
    assert 'class="passkey-ui app-shell"' in login.text or "passkey-ui app-shell" in login.text


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
