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
