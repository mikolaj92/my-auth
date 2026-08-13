from __future__ import annotations

import dataclasses
import asyncio
import importlib
import subprocess
import sys
import textwrap
import tomllib
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
    PasskeyCredential,
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

    async def prepare(_request: Request, _username: str):
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


def test_repository_app_factory_pin_matches_lock() -> None:
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))

    assert project["tool"]["uv"]["sources"]["app-factory"]["tag"] == "v0.6.3"
    app_factory = next(
        package for package in lock["package"] if package["name"] == "app-factory"
    )
    assert app_factory["version"] == "0.6.3"
    assert "tag=v0.6.3" in app_factory["source"]["git"]


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


def test_packaged_css_centers_passkey_panel_in_app_factory_shell() -> None:
    css = (
        files("my_auth.fastapi_htmx")
        .joinpath("static/passkey-ui.css")
        .read_text(encoding="utf-8")
    )

    assert ".passkey-shell" in css
    assert "place-items: center" in css
    # Full-width header: do not grid-center the entire .app-main when a top bar exists.
    assert ".app-main:has(> .app-main-header):has(.passkey-card)" in css
    assert "flex-direction: column" in css


def test_login_and_register_templates_wrap_panel_in_passkey_shell() -> None:
    """app-factory body is app-shell, not passkey-ui — templates must wrap."""
    package = files("my_auth.fastapi_htmx")
    for name in ("templates/login.html", "templates/register.html"):
        html = package.joinpath(name).read_text(encoding="utf-8")
        assert 'class="passkey-shell"' in html


def test_packaged_pages_extend_identity_shells_not_bare_shell() -> None:
    """Login/register stay on shell.html; ceremony pages use identity frames."""
    package = files("my_auth.fastapi_htmx")
    login = package.joinpath("templates/login.html").read_text(encoding="utf-8")
    register = package.joinpath("templates/register.html").read_text(encoding="utf-8")
    capability = package.joinpath("templates/capability_registration.html").read_text(
        encoding="utf-8"
    )
    credentials = package.joinpath("templates/credential_management.html").read_text(
        encoding="utf-8"
    )

    assert '{% extends "app_factory/shell.html" %}' in login
    assert '{% extends "app_factory/shell.html" %}' in register
    assert '{% extends "app_factory/identity_public_shell.html" %}' in capability
    assert "{% block identity_panel %}" in capability
    assert "data-platform-identity-ceremony" in capability
    assert '{% include "app_factory/identity_public_state.html" %}' in capability
    assert '{% extends "app_factory/identity_authenticated_shell.html" %}' in credentials
    assert 'data-platform-identity-ceremony="credentials"' in credentials
    assert "{% block content %}" in credentials
    assert "{% block identity_panel %}" not in credentials


def test_passkey_panels_use_basecoat_button_and_field_conventions() -> None:
    """Basecoat 1.0: btn + data-variant, not btn-primary; fields use .field."""
    package = files("my_auth.fastapi_htmx")
    login = package.joinpath("templates/_login_panel.html").read_text(encoding="utf-8")
    register = package.joinpath("templates/_register_panel.html").read_text(
        encoding="utf-8"
    )
    for html in (login, register):
        assert "btn-primary" not in html
        assert 'data-variant="primary"' in html
        assert 'class="btn' in html or "class='btn" in html
    assert 'class="field"' in register
    js = package.joinpath("static/passkey-ui.js").read_text(encoding="utf-8")
    assert 'dataset.variant = "destructive"' in js


def test_passkey_panels_use_basecoat_semantic_card_slots() -> None:
    """Basecoat 1.0 pads .card > header|section, not .card-header/.card-content."""
    package = files("my_auth.fastapi_htmx")
    for name in (
        "templates/_login_panel.html",
        "templates/_register_panel.html",
    ):
        html = package.joinpath(name).read_text(encoding="utf-8")
        # strip jinja comments before class-name assertions
        body = "\n".join(
            line for line in html.splitlines() if not line.strip().startswith("{#")
        )
        assert "<header" in body
        assert 'class="passkey-card__header"' in body or "passkey-card__header" in body
        assert 'class="card-header' not in body
        assert 'class="card-content' not in body
        assert "class='card-header" not in body
        assert "class='card-content" not in body


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


def test_host_can_hide_anonymous_registration_link() -> None:
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
    install_passkey_ui(
        app,
        platform=platform,
        service=_service(),
        hooks=_hooks(),
        config=PasskeyUiConfig(show_registration_link=lambda _request: False),
    )

    login = TestClient(app).get("/login")

    assert login.status_code == 200
    assert 'href="/register"' not in login.text


def test_host_can_replace_anonymous_registration_link_target() -> None:
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
    install_passkey_ui(
        app,
        platform=platform,
        service=_service(),
        hooks=_hooks(),
        config=PasskeyUiConfig(
            registration_link_url=lambda _request: "/passkey/recovery"
        ),
    )

    login = TestClient(app).get("/login")

    assert login.status_code == 200
    assert 'href="/passkey/recovery"' in login.text
    assert 'href="/register"' not in login.text


def test_installed_ui_renders_distinct_activation_and_recovery_pages() -> None:
    app, _, ui = _app()
    client = TestClient(app)

    activation = client.get("/activate?capability=invite-token")
    recovery = client.get("/recover?capability=recovery-token")
    invalid = client.get("/recover")

    assert activation.status_code == recovery.status_code == invalid.status_code == 200
    assert "Activate your account" in activation.text
    assert 'data-registration-kind="invitation"' in activation.text
    assert 'data-capability="invite-token"' in activation.text
    assert "data-platform-identity-public" in activation.text
    assert 'data-platform-identity-ceremony="activation"' in activation.text
    assert "Recover access" in recovery.text
    assert 'data-registration-kind="recovery"' in recovery.text
    assert 'data-capability="recovery-token"' in recovery.text
    assert "data-platform-identity-public" in recovery.text
    assert 'data-platform-identity-ceremony="recovery"' in recovery.text
    assert "invalid or no longer available" in invalid.text
    assert "data-platform-identity-public-state" in invalid.text
    assert "data-platform-identity-public" in invalid.text
    assert 'data-capability=' not in invalid.text
    controller = client.get(f"{ui.static_mount_path}/passkey-ui.js").text
    helper = client.get(f"{ui.static_mount_path}/passkey.js").text
    assert "registrationKind" in controller
    assert "registration_kind" in helper


def test_capability_pages_support_locale_and_request_aware_success_redirects() -> None:
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
    install_passkey_ui(
        app,
        platform=platform,
        service=_service(),
        hooks=_hooks(),
        config=PasskeyUiConfig(
            default_locale="pl",
            activation_success_url="/welcome",
            recovery_success_url="/login?recovered=1",
        ),
    )
    client = TestClient(app)
    activation = client.get("/activate?capability=token")
    recovery = client.get("/recover?capability=token")
    assert "Aktywuj konto" in activation.text
    assert 'data-success-url="/welcome"' in activation.text
    assert "Odzyskaj dostęp" in recovery.text
    assert 'data-success-url="/login?recovered=1"' in recovery.text


def test_authenticated_credential_page_is_owner_scoped_and_mutable() -> None:
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
    user = PasskeyUser("owner", b"owner-handle", "owner")
    other = PasskeyUser("other", b"other-handle", "other")
    store = MemoryCredentialStore()
    for subject, credential_id in ((user, b"first"), (user, b"second"), (other, b"other")):
        store.save_registration(
            VerifiedRegistration(
                subject,
                PasskeyCredential(credential_id, subject.user_id, b"key-" + credential_id),
            )
        )
    service = PasskeyService(
        config=PasskeyConfig(
            rp_id="localhost", rp_name="Demo", origin="http://localhost"
        ),
        challenges=MemoryChallengeStore(),
        credentials=store,
    )
    hooks = _hooks()
    hooks = dataclasses.replace(hooks, get_session_user=lambda _request: user)
    install_passkey_ui(
        app, platform=platform, service=service, hooks=hooks, config=PasskeyUiConfig()
    )
    client = TestClient(app)

    page = client.get("/account/passkeys")
    assert page.status_code == 200
    assert "Zmlyc3Q" in page.text and "c2Vjb25k" in page.text
    assert "b3RoZXI" not in page.text
    assert "data-platform-identity-authenticated" in page.text
    assert 'data-platform-identity-ceremony="credentials"' in page.text
    labeled = client.post(
        "/api/auth/credentials/Zmlyc3Q/label", json={"label": "Laptop"}
    )
    assert labeled.status_code == 200
    assert "Laptop" in labeled.text
    assert client.post(
        "/api/auth/credentials/b3RoZXI/label", json={"label": "No"}
    ).status_code == 404
    assert client.delete("/api/auth/credentials/c2Vjb25k").status_code == 200
    final = client.delete("/api/auth/credentials/Zmlyc3Q")
    assert final.status_code == 409
    assert "final passkey credential" in final.json()["detail"]


def test_credential_page_requires_authentication() -> None:
    app, _, _ = _app()
    client = TestClient(app)
    assert client.get("/account/passkeys").status_code == 401


def test_installed_ui_renders_packaged_account_registration_panel() -> None:
    _, _, ui = _app()
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/account",
            "headers": [],
            "query_string": b"",
        }
    )

    panel = asyncio.run(ui.render_account_panel(request))

    assert 'data-passkey-form="register"' in panel
    assert 'data-options-url="/api/auth/register/options"' in panel
    assert f'href="{ui.config.static_url_path}/passkey-ui.css"' in panel
    assert f'src="{ui.config.static_url_path}/passkey-ui.js"' in panel
    assert 'id="passkey-ui-messages"' in panel


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


def test_login_locale_switches_copy_and_sets_cookie() -> None:
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
    install_passkey_ui(
        app,
        platform=platform,
        service=_service(),
        hooks=_hooks(),
        config=PasskeyUiConfig(
            locale_cookie_name="app_lang",
            supported_locales=("pl", "en", "de"),
            default_locale="pl",
        ),
    )
    client = TestClient(app)

    pl = client.get("/login?lang=pl")
    assert pl.status_code == 200
    assert 'lang="pl"' in pl.text
    assert "Zaloguj się bez hasła" in pl.text
    assert "Kontynuuj z kluczem dostępu" in pl.text
    assert "Zaloguj się telefonem (kod QR)" in pl.text
    assert "Nie masz konta? Zarejestruj klucz dostępu" in pl.text
    assert 'href="/register"' in pl.text
    assert "Sign in without a password" not in pl.text
    assert "app_lang=pl" in pl.headers.get("set-cookie", "")
    assert 'id="passkey-ui-messages"' in pl.text
    assert "js_waiting_prompt" in pl.text

    en = client.get("/login?lang=en")
    assert en.status_code == 200
    assert 'lang="en"' in en.text
    assert "Sign in without a password" in en.text
    assert "Continue with passkey" in en.text
    assert "Sign in with a phone (QR code)" in en.text
    assert "No account? Register a passkey" in en.text
    assert "Zaloguj się bez hasła" not in en.text
    assert "app_lang=en" in en.headers.get("set-cookie", "")

    de = client.get("/login?lang=de")
    assert de.status_code == 200
    assert 'lang="de"' in de.text
    assert "Ohne Passwort anmelden" in de.text
    assert "Mit Passkey fortfahren" in de.text
    assert "Mit einem Telefon anmelden (QR-Code)" in de.text
    assert "Noch kein Konto? Passkey registrieren" in de.text
    assert "Sign in without a password" not in de.text
    assert "app_lang=de" in de.headers.get("set-cookie", "")

    # Cookie alone resolves locale when ?lang= is absent.
    cookied = client.get("/login", cookies={"app_lang": "en"})
    assert cookied.status_code == 200
    assert 'lang="en"' in cookied.text
    assert "Sign in without a password" in cookied.text

    cookied_de = client.get("/login", cookies={"app_lang": "de"})
    assert cookied_de.status_code == 200
    assert 'lang="de"' in cookied_de.text
    assert "Ohne Passwort anmelden" in cookied_de.text


def test_phone_login_uses_native_webauthn_hybrid_hint() -> None:
    app, _, ui = _app()
    client = TestClient(app)
    controller = client.get(f"{ui.static_mount_path}/passkey-ui.js").text
    helper = client.get(f"{ui.static_mount_path}/passkey.js").text

    assert 'submitPasskeyForm(form, "hybrid")' in controller
    assert 'hint === "hybrid" ? messages.js_hybrid_prompt' in controller
    assert "if (hint) options.hints = [hint]" in helper


def test_login_uses_full_width_content_class_not_app_content_inner() -> None:
    app, _, _ = _app()
    client = TestClient(app)
    html = client.get("/login").text
    assert 'class="passkey-content"' in html
    # Avoid the factory content max-width wrapper on the login column.
    assert 'id="main-content"\n        class="app-content-inner"' not in html


def test_packaged_css_forces_full_width_header_on_app_shell() -> None:
    css = (
        files("my_auth.fastapi_htmx")
        .joinpath("static/passkey-ui.css")
        .read_text(encoding="utf-8")
    )
    assert "body.app-shell .app-main > .app-main-header" in css
    assert "align-self: stretch" in css
    # place-items centers only the panel, never the whole main column.
    assert ".passkey-shell" in css
    assert "place-items: center" in css
    assert (
        ".app-main:has(.passkey-card) {\n  display: grid;\n  place-items: center"
        not in css
    )
