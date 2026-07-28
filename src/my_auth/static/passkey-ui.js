import { loginPasskey, registerPasskey } from "./passkey.js";

const successMessages = {
  login: "Passkey sign-in succeeded.",
  register: "Passkey registration succeeded.",
};

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
  setStatus(form, "This browser does not support WebAuthn passkeys with PublicKeyCredential.", "error");
  return false;
}

function handleSuccess(form, action) {
  const successUrl = form.dataset.successUrl;
  if (successUrl) {
    window.location.assign(successUrl);
    return;
  }
  setStatus(form, successMessages[action], "success");
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
    throw new Error("Username is required.");
  }
  if (/\s/.test(username)) {
    throw new Error("Username must not contain spaces.");
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
  setStatus(form, "Waiting for your passkey prompt.", "pending");
  try {
    if (action === "register") {
      await submitRegister(form);
      return;
    }
    await submitLogin(form);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Passkey request failed.";
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
