"""Optional real-browser coverage for passkey-ui.js.

Default suite stays dep-free. These tests skip unless Playwright browsers
are available (``uv sync --extra browser && uv run playwright install chromium``).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from importlib.resources import files
from typing import Any
from urllib.parse import urlparse

import pytest

pytest.importorskip("playwright.sync_api")
from fastapi import Request
from playwright.sync_api import Page, sync_playwright

STATIC = files("my_auth.fastapi_htmx").joinpath("static")
CONTROLLER = STATIC.joinpath("passkey-ui.js").read_text(encoding="utf-8")
HELPER = STATIC.joinpath("passkey.js").read_text(encoding="utf-8")
MESSAGES = {
    "js_insecure_context": "Klucze dostępu wymagają bezpiecznego połączenia HTTPS.",
    "js_unsupported": (
        "Ta przeglądarka nie obsługuje kluczy WebAuthn (PublicKeyCredential)."
    ),
}


def _login_page(messages: dict[str, str]) -> str:
    payload = json.dumps(messages)
    return f"""<!doctype html>
    <html lang="pl">
      <head><meta charset="utf-8"></head>
      <body>
        <form
          data-passkey-form="login"
          data-conditional-ui="true"
          data-status-target="passkey-login-status"
          data-options-url="/unused/options"
          data-verify-url="/unused/verify"
        >
          <label for="passkey-login-username">Nazwa użytkownika (opcjonalnie)</label>
          <input id="passkey-login-username" name="username" autocomplete="username webauthn">
          <button type="submit">Kontynuuj z kluczem dostępu</button>
          <button type="button" data-passkey-hybrid>Zaloguj się telefonem (kod QR)</button>
        </form>
        <p id="passkey-login-status">Oczekiwanie na monit WebAuthn klucza dostępu.</p>
        <script type="application/json" id="passkey-ui-messages">{payload}</script>
        <script type="module" src="/passkey-ui.js"></script>
      </body>
    </html>"""


def _install_routes(page: Page) -> None:
    def handle(route: Any) -> None:
        path = urlparse(route.request.url).path
        if path == "/passkey-ui.js":
            route.fulfill(body=CONTROLLER, content_type="text/javascript")
            return
        if path == "/passkey.js":
            route.fulfill(body=HELPER, content_type="text/javascript")
            return
        if path == "/unused/options":
            route.fulfill(
                body=json.dumps({"challenge": "AA", "rpId": "localhost"}),
                content_type="application/json",
            )
            return
        route.fulfill(
            body=_login_page(MESSAGES),
            content_type="text/html; charset=utf-8",
        )

    page.route("**/*", handle)


@pytest.fixture
def browser_page() -> Iterator[Page]:
    with sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch(headless=True)
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"chromium unavailable: {exc}")
        context = browser.new_context()
        page = context.new_page()
        page.set_default_timeout(8_000)
        try:
            yield page
        finally:
            context.close()
            browser.close()


def test_explains_https_when_webauthn_is_hidden_by_insecure_context(
    browser_page: Page,
) -> None:
    _install_routes(browser_page)
    browser_page.goto("http://webauthn.test/login")
    status = browser_page.locator("#passkey-login-status")
    status.wait_for()
    assert status.inner_text() == MESSAGES["js_insecure_context"]
    assert status.get_attribute("data-state") == "error"


def test_keeps_neutral_state_when_webauthn_is_available(browser_page: Page) -> None:
    browser_page.add_init_script(
        """
        Object.defineProperty(window, "PublicKeyCredential", {
          configurable: true,
          value: function PublicKeyCredential() {},
        });
        Object.defineProperty(navigator, "credentials", {
          configurable: true,
          value: {},
        });
        """
    )
    _install_routes(browser_page)
    browser_page.goto("http://localhost/login")
    status = browser_page.locator("#passkey-login-status")
    assert status.inner_text() == "Oczekiwanie na monit WebAuthn klucza dostępu."
    assert status.get_attribute("data-state") != "error"


def test_keeps_unsupported_browser_diagnosis_on_trusted_origin(
    browser_page: Page,
) -> None:
    browser_page.add_init_script(
        """
        Object.defineProperty(window, "PublicKeyCredential", {
          configurable: true,
          value: undefined,
        });
        """
    )
    _install_routes(browser_page)
    browser_page.goto("http://localhost/login")
    status = browser_page.locator("#passkey-login-status")
    assert status.inner_text() == MESSAGES["js_unsupported"]
    assert status.get_attribute("data-state") == "error"


def test_starts_both_login_actions_without_misreporting_cancel(
    browser_page: Page,
) -> None:
    browser_page.add_init_script(
        """
        window.__webauthnCalls = [];
        const credentialApi = window.PublicKeyCredential || function PublicKeyCredential() {};
        Object.defineProperty(credentialApi, "isConditionalMediationAvailable", {
          configurable: true,
          value: async () => false,
        });
        Object.defineProperty(window, "PublicKeyCredential", {
          configurable: true,
          value: credentialApi,
        });
        Object.defineProperty(navigator, "credentials", {
          configurable: true,
          value: {
            get: async ({ publicKey }) => {
              window.__webauthnCalls.push(publicKey.hints || []);
              throw new DOMException("The operation was cancelled.", "AbortError");
            },
          },
        });
        """
    )
    _install_routes(browser_page)
    browser_page.goto("http://localhost/login")
    browser_page.get_by_role("button", name="Kontynuuj z kluczem dostępu").click()
    browser_page.wait_for_function("() => window.__webauthnCalls.length === 1")
    assert (
        "nie obsługuje kluczy WebAuthn"
        not in browser_page.locator("#passkey-login-status").inner_text()
    )
    assert browser_page.evaluate("() => window.__webauthnCalls[0]") == []

    browser_page.get_by_role("button", name="Zaloguj się telefonem").click()
    browser_page.wait_for_function("() => window.__webauthnCalls.length === 2")
    assert (
        "nie obsługuje kluczy WebAuthn"
        not in browser_page.locator("#passkey-login-status").inner_text()
    )


def test_starts_conditional_autofill_when_browser_reports_support(
    browser_page: Page,
) -> None:
    browser_page.add_init_script(
        """
        window.__conditionalCalls = [];
        const credentialApi = window.PublicKeyCredential || function PublicKeyCredential() {};
        Object.defineProperty(credentialApi, "isConditionalMediationAvailable", {
          configurable: true,
          value: async () => true,
        });
        Object.defineProperty(window, "PublicKeyCredential", {
          configurable: true,
          value: credentialApi,
        });
        Object.defineProperty(navigator, "credentials", {
          configurable: true,
          value: {
            get: async ({ mediation, signal }) => {
              window.__conditionalCalls.push({ mediation, hasSignal: Boolean(signal) });
              throw new DOMException("The operation was cancelled.", "AbortError");
            },
          },
        });
        """
    )
    _install_routes(browser_page)
    browser_page.goto("http://localhost/login")
    username = browser_page.locator("#passkey-login-username")
    assert username.is_visible()
    assert username.get_attribute("autocomplete") == "username webauthn"
    browser_page.wait_for_function("() => window.__conditionalCalls.length === 1")
    assert browser_page.evaluate("() => window.__conditionalCalls[0]") == {
        "mediation": "conditional",
        "hasSignal": True,
    }
    assert (
        browser_page.locator("#passkey-login-status").get_attribute("data-state")
        != "error"
    )


def test_leaves_manual_login_working_without_conditional_mediation(
    browser_page: Page,
) -> None:
    browser_page.add_init_script(
        """
        window.__conditionalCalls = [];
        const credentialApi = window.PublicKeyCredential || function PublicKeyCredential() {};
        Object.defineProperty(credentialApi, "isConditionalMediationAvailable", {
          configurable: true,
          value: async () => false,
        });
        Object.defineProperty(window, "PublicKeyCredential", {
          configurable: true,
          value: credentialApi,
        });
        Object.defineProperty(navigator, "credentials", {
          configurable: true,
          value: {
            get: async ({ mediation }) => {
              window.__conditionalCalls.push(mediation || "manual");
              throw new DOMException("The operation was cancelled.", "AbortError");
            },
          },
        });
        """
    )
    _install_routes(browser_page)
    browser_page.goto("http://localhost/login")
    browser_page.wait_for_timeout(50)
    assert browser_page.evaluate("() => window.__conditionalCalls") == []
    browser_page.get_by_role("button", name="Kontynuuj z kluczem dostępu").click()
    browser_page.wait_for_function("() => window.__conditionalCalls.length === 1")
    assert browser_page.evaluate("() => window.__conditionalCalls[0]") == "manual"


def test_aborts_conditional_mediation_before_manual_login(browser_page: Page) -> None:
    browser_page.add_init_script(
        """
        window.__conditionalCalls = [];
        window.__conditionalAborts = 0;
        const credentialApi = window.PublicKeyCredential || function PublicKeyCredential() {};
        Object.defineProperty(credentialApi, "isConditionalMediationAvailable", {
          configurable: true,
          value: async () => true,
        });
        Object.defineProperty(window, "PublicKeyCredential", {
          configurable: true,
          value: credentialApi,
        });
        Object.defineProperty(navigator, "credentials", {
          configurable: true,
          value: {
            get: ({ mediation, signal }) => new Promise((resolve, reject) => {
              window.__conditionalCalls.push(mediation || "manual");
              signal?.addEventListener("abort", () => {
                window.__conditionalAborts += 1;
                reject(new DOMException("The operation was cancelled.", "AbortError"));
              }, { once: true });
              if (mediation !== "conditional") {
                reject(new DOMException("The operation was cancelled.", "AbortError"));
              }
            }),
          },
        });
        """
    )
    _install_routes(browser_page)
    browser_page.goto("http://localhost/login")
    browser_page.wait_for_function("() => window.__conditionalCalls.length === 1")
    browser_page.get_by_role("button", name="Kontynuuj z kluczem dostępu").click()
    browser_page.wait_for_function("() => window.__conditionalAborts === 1")
    browser_page.wait_for_function("() => window.__conditionalCalls.length === 2")
    assert (
        browser_page.locator("#passkey-login-status").get_attribute("data-state")
        != "error"
    )
    browser_page.locator("[data-passkey-form=login]").evaluate(
        "(form) => form.remove()"
    )
    browser_page.wait_for_timeout(50)
    assert browser_page.evaluate("() => window.__conditionalAborts") == 1


def test_rebinds_login_form_after_htmx_swap(browser_page: Page) -> None:
    browser_page.add_init_script(
        """
        window.__conditionalCalls = [];
        const credentialApi = window.PublicKeyCredential || function PublicKeyCredential() {};
        Object.defineProperty(credentialApi, "isConditionalMediationAvailable", {
          configurable: true,
          value: async () => false,
        });
        Object.defineProperty(window, "PublicKeyCredential", {
          configurable: true,
          value: credentialApi,
        });
        Object.defineProperty(navigator, "credentials", {
          configurable: true,
          value: {
            get: async ({ mediation }) => {
              window.__conditionalCalls.push(mediation || "manual");
              throw new DOMException("The operation was cancelled.", "AbortError");
            },
          },
        });
        """
    )
    _install_routes(browser_page)
    browser_page.goto("http://localhost/login")
    browser_page.evaluate(
        """() => {
          const oldForm = document.querySelector("[data-passkey-form=login]");
          const newForm = oldForm.cloneNode(true);
          newForm.dataset.passkeyBound = "false";
          oldForm.replaceWith(newForm);
          document.dispatchEvent(new CustomEvent("htmx:afterSwap", {
            detail: { elt: newForm },
          }));
        }"""
    )
    browser_page.get_by_role("button", name="Kontynuuj z kluczem dostępu").click()
    browser_page.wait_for_function("() => window.__conditionalCalls.length === 1")


def _check_packaged_shell_layout(page: Page, css: str | None = None) -> None:
    """Exercise real package templates/assets through the in-process ASGI app."""
    from app_factory.fastapi import install_app_factory_ui
    from app_factory.platform import (
        PlatformConfig,
        PlatformUser,
        build_platform_context,
    )
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse, RedirectResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.testclient import TestClient
    from jinja2 import ChoiceLoader, DictLoader
    from my_auth.fastapi_htmx.config import PasskeyUiConfig
    from my_auth.fastapi_htmx.templates import (
        PasskeyTemplateRenderer,
        build_template_environment,
    )

    app = FastAPI()
    config = PasskeyUiConfig()
    environment = build_template_environment(config)
    environment.loader = ChoiceLoader(
        [
            DictLoader(
                {
                    "layout_account.html": (
                        '{% extends "app_factory/product_shell.html" %}'
                        "{% block content %}{{ panel | safe }}"
                        '{% include "app_factory/platform_session.html" %}'
                        "{% endblock %}"
                    ),
                    "layout_login_no_header.html": (
                        '{% extends "login.html" %}{% block header %}{% endblock %}'
                    ),
                    "layout_register_no_header.html": (
                        '{% extends "register.html" %}{% block header %}{% endblock %}'
                    ),
                }
            ),
            environment.loader,
        ]
    )
    install_app_factory_ui(app, environments=[environment])
    renderer = PasskeyTemplateRenderer(environment, config)
    app.mount(config.static_mount_path, StaticFiles(directory=str(STATIC)))
    posts: list[str] = []

    @app.get("/auth/{ceremony}")
    async def ceremony(request: Request, ceremony: str) -> Any:
        template = f"{ceremony}.html"
        if request.query_params.get("header") == "none":
            template = f"layout_{ceremony}_no_header.html"
        return await renderer._render(template, request)

    @app.get("/account")
    async def account(request: Request) -> Any:
        context = build_platform_context(
            PlatformConfig(app_name="Synthetic product"),
            user=PlatformUser("Synthetic user"),
            current_path="/account",
        )
        return HTMLResponse(
            environment.get_template("layout_account.html").render(
                **context, panel=await renderer.render_account_panel(request)
            )
        )

    @app.post("/logout")
    async def logout() -> Any:
        posts.append("POST")
        return RedirectResponse("/auth/login", status_code=303)

    with TestClient(app) as client:

        def handle(route: Any) -> None:
            parsed = urlparse(route.request.url)
            assert parsed.netloc == "layout.test"
            if css is not None and parsed.path.endswith("/passkey-ui.css"):
                route.fulfill(body=css, content_type="text/css")
                return
            target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            response = client.request(
                route.request.method, target, follow_redirects=True
            )
            headers = dict(response.headers)
            headers.pop("content-length", None)
            route.fulfill(
                status=response.status_code, headers=headers, body=response.content
            )

        page.route("**/*", handle)
        try:
            for width, height in ((1280, 800), (390, 844)):
                page.set_viewport_size({"width": width, "height": height})
                for name in ("login", "register"):
                    for header in ("default", "none"):
                        page.goto(
                            f"http://layout.test/auth/{name}?header={header}",
                            wait_until="networkidle",
                        )
                        main = page.locator(".app-main").bounding_box()
                        card = page.locator(".passkey-card").bounding_box()
                        assert main is not None and card is not None
                        assert abs(main["x"]) < 1
                        assert abs(main["width"] - width) < 1
                        assert abs(card["x"] + card["width"] / 2 - width / 2) < 1
                        assert (
                            page.evaluate("document.documentElement.scrollWidth")
                            <= width
                        )
                        if header == "default":
                            bar = page.locator(".app-main-header").bounding_box()
                            assert bar is not None and abs(bar["width"] - width) < 1
                        else:
                            assert page.locator(".app-main-header").count() == 0
                page.goto("http://layout.test/account", wait_until="networkidle")
                main = page.locator(".app-main").bounding_box()
                sidebar = page.locator("#sidebar nav").bounding_box()
                assert main is not None and sidebar is not None
                if width >= 768:
                    assert main["x"] >= sidebar["x"] + sidebar["width"] - 1
                before = len(posts)
                page.get_by_role("button", name="Log out", exact=True).click()
                page.locator("[data-passkey-form=login]").wait_for()
                assert len(posts) == before + 1
        finally:
            page.unroute("**/*", handle)


def test_embedded_account_preserves_sidebar_and_standalone_geometry(
    browser_page: Page,
) -> None:
    _check_packaged_shell_layout(browser_page)
