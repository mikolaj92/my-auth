import { loginPasskey, registerPasskey } from "./passkey.js";

const defaultMessages = {
  js_login_success: "Passkey sign-in succeeded.",
  js_register_success: "Passkey registration succeeded.",
  js_unsupported:
    "This browser does not support WebAuthn passkeys with PublicKeyCredential.",
  js_waiting_prompt: "Waiting for your passkey prompt.",
  js_request_failed: "Passkey request failed.",
  js_username_required: "Username is required.",
  js_username_spaces: "Username must not contain spaces.",
};

function loadMessages() {
  const el = document.getElementById("passkey-ui-messages");
  if (!el || !el.textContent) return { ...defaultMessages };
  try {
    const parsed = JSON.parse(el.textContent);
    if (parsed && typeof parsed === "object") {
      return { ...defaultMessages, ...parsed };
    }
  } catch (_) {
    /* keep defaults */
  }
  return { ...defaultMessages };
}

const messages = loadMessages();

function csrfHeaders(form) {
  const headerName = form.dataset.csrfHeader;
  const token = form.dataset.csrfToken;
  if (!headerName || !token) return {};
  return { [headerName]: token };
}

function statusTarget(form) {
  const targetId = form.dataset.statusTarget;
  if (!targetId) return null;
  return document.getElementById(targetId);
}

function setStatus(form, message, state) {
  const target = statusTarget(form);
  if (!target) return;
  target.dataset.state = state;
  // Basecoat 1.0 alert variants (not custom color CSS alone).
  if (state === "error") {
    target.dataset.variant = "destructive";
  } else {
    delete target.dataset.variant;
  }
  target.textContent = message;
}

function assertWebAuthnSupport(form) {
  if (window.PublicKeyCredential && navigator.credentials) return true;
  setStatus(form, messages.js_unsupported, "error");
  return false;
}

function handleSuccess(form, action) {
  const successUrl = form.dataset.successUrl;
  if (successUrl) {
    window.location.assign(successUrl);
    return;
  }
  const key = action === "register" ? "js_register_success" : "js_login_success";
  setStatus(form, messages[key], "success");
}

async function submitLogin(form) {
  await loginPasskey({
    optionsUrl: form.dataset.optionsUrl,
    verifyUrl: form.dataset.verifyUrl,
    fetchOptions: { headers: csrfHeaders(form) },
  });
  handleSuccess(form, "login");
}

async function submitRegister(form) {
  const usernameInput = form.elements.namedItem("username");
  const displayNameInput = form.elements.namedItem("display_name");
  const username = usernameInput instanceof HTMLInputElement ? usernameInput.value.trim() : "";
  const displayName = displayNameInput instanceof HTMLInputElement ? displayNameInput.value.trim() : "";
  if (!username) {
    throw new Error(messages.js_username_required);
  }
  if (/\s/.test(username)) {
    throw new Error(messages.js_username_spaces);
  }
  await registerPasskey({
    optionsUrl: form.dataset.optionsUrl,
    verifyUrl: form.dataset.verifyUrl,
    username,
    displayName: displayName || undefined,
    fetchOptions: { headers: csrfHeaders(form) },
  });
  handleSuccess(form, "register");
}

async function submitPasskeyForm(form) {
  if (!assertWebAuthnSupport(form)) return;
  const action = form.dataset.passkeyForm;
  setStatus(form, messages.js_waiting_prompt, "pending");
  try {
    if (action === "register") {
      await submitRegister(form);
      return;
    }
    await submitLogin(form);
  } catch (error) {
    const message = error instanceof Error ? error.message : messages.js_request_failed;
    setStatus(form, message, "error");
  }
}

function bindPasskeyForm(form) {
  assertWebAuthnSupport(form);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void submitPasskeyForm(form);
  });
}

for (const form of document.querySelectorAll("[data-passkey-form]")) {
  bindPasskeyForm(form);
}
