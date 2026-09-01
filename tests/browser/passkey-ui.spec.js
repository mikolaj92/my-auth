const fs = require("node:fs");
const path = require("node:path");
const { test, expect } = require("@playwright/test");

const staticDirectory = path.resolve(
  __dirname,
  "../../src/my_auth/fastapi_htmx/static",
);
const controller = fs.readFileSync(
  path.join(staticDirectory, "passkey-ui.js"),
  "utf8",
);
const helper = fs.readFileSync(path.join(staticDirectory, "passkey.js"), "utf8");

function loginPage(messages) {
  return `<!doctype html>
    <html lang="pl">
      <head><meta charset="utf-8"></head>
      <body>
        <form
          data-passkey-form="login"
          data-status-target="passkey-login-status"
          data-options-url="/unused/options"
          data-verify-url="/unused/verify"
        >
          <button type="submit">Kontynuuj z kluczem dostępu</button>
          <button type="button" data-passkey-hybrid>Zaloguj się telefonem (kod QR)</button>
        </form>
        <p id="passkey-login-status">Oczekiwanie na monit WebAuthn klucza dostępu.</p>
        <script type="application/json" id="passkey-ui-messages">${JSON.stringify(messages)}</script>
        <script type="module" src="/passkey-ui.js"></script>
      </body>
    </html>`;
}

async function installRoutes(page) {
  await page.route("**/*", async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    if (pathname === "/passkey-ui.js") {
      await route.fulfill({ body: controller, contentType: "text/javascript" });
      return;
    }
    if (pathname === "/passkey.js") {
      await route.fulfill({ body: helper, contentType: "text/javascript" });
      return;
    }
    if (pathname === "/unused/options") {
      await route.fulfill({
        body: JSON.stringify({ challenge: "AA", rpId: "localhost" }),
        contentType: "application/json",
      });
      return;
    }
    await route.fulfill({
      body: loginPage({
        js_insecure_context:
          "Klucze dostępu wymagają bezpiecznego połączenia HTTPS.",
        js_unsupported:
          "Ta przeglądarka nie obsługuje kluczy WebAuthn (PublicKeyCredential).",
      }),
      contentType: "text/html; charset=utf-8",
    });
  });
}

test("explains the HTTPS requirement when WebAuthn is hidden by an insecure context", async ({ page }) => {
  await installRoutes(page);

  await page.goto("http://webauthn.test/login");

  await expect(page.locator("#passkey-login-status")).toHaveText(
    "Klucze dostępu wymagają bezpiecznego połączenia HTTPS.",
  );
  await expect(page.locator("#passkey-login-status")).toHaveAttribute(
    "data-state",
    "error",
  );
});

test("keeps the neutral state when WebAuthn is available on a trusted origin", async ({ page }) => {
  await installRoutes(page);

  await page.goto("http://localhost/login");

  await expect(page.locator("#passkey-login-status")).toHaveText(
    "Oczekiwanie na monit WebAuthn klucza dostępu.",
  );
  await expect(page.locator("#passkey-login-status")).not.toHaveAttribute(
    "data-state",
    "error",
  );
});

test("keeps the unsupported-browser diagnosis for a missing API on a trusted origin", async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(window, "PublicKeyCredential", {
      configurable: true,
      value: undefined,
    });
  });
  await installRoutes(page);
  await page.goto("http://localhost/login");

  await expect(page.locator("#passkey-login-status")).toHaveText(
    "Ta przeglądarka nie obsługuje kluczy WebAuthn (PublicKeyCredential).",
  );
  await expect(page.locator("#passkey-login-status")).toHaveAttribute(
    "data-state",
    "error",
  );
});

test("starts both login actions without misreporting a cancelled prompt", async ({ page }) => {
  await page.addInitScript(() => {
    window.__webauthnCalls = [];
    Object.defineProperty(navigator, "credentials", {
      configurable: true,
      value: {
        get: async ({ publicKey }) => {
          window.__webauthnCalls.push(publicKey.hints || []);
          throw new DOMException("The operation was cancelled.", "AbortError");
        },
      },
    });
  });
  await installRoutes(page);
  await page.goto("http://localhost/login");

  await page.getByRole("button", { name: "Kontynuuj z kluczem dostępu" }).click();
  await expect.poll(() => page.evaluate(() => window.__webauthnCalls.length)).toBe(1);
  await expect(page.locator("#passkey-login-status")).not.toHaveText(
    /nie obsługuje kluczy WebAuthn/,
  );
  expect(await page.evaluate(() => window.__webauthnCalls[0])).toEqual([]);

  await page.getByRole("button", { name: "Zaloguj się telefonem" }).click();
  await expect.poll(() => page.evaluate(() => window.__webauthnCalls.length)).toBe(2);
  await expect(page.locator("#passkey-login-status")).not.toHaveText(
    /nie obsługuje kluczy WebAuthn/,
  );
});
