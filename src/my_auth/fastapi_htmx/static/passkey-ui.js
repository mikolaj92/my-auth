import { loginPasskey, registerPasskey } from "./passkey.js";

const defaultMessages = {
  js_login_success: "Passkey sign-in succeeded.",
  js_register_success: "Passkey registration succeeded.",
  js_insecure_context: "Passkeys require a secure HTTPS connection.",
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
const conditionalControllers = new WeakMap();

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

function isAbortError(error) {
  return error instanceof DOMException && error.name === "AbortError";
}

function setErrorUnlessAborted(form, error) {
  if (isAbortError(error)) return;
  setStatus(
    form,
    error instanceof Error ? error.message : messages.js_request_failed,
    "error",
  );
}

function abortConditionalLogin(form) {
  conditionalControllers.get(form)?.abort();
  conditionalControllers.delete(form);
}

function assertWebAuthnSupport(form) {
  if (!window.isSecureContext) {
    setStatus(form, messages.js_insecure_context, "error");
    return false;
  }
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

async function submitLogin(form, hint) {
  abortConditionalLogin(form);
  const controller = new AbortController();
  conditionalControllers.set(form, controller);
  try {
    await loginPasskey({
      optionsUrl: form.dataset.optionsUrl,
      verifyUrl: form.dataset.verifyUrl,
      hint,
      signal: controller.signal,
      fetchOptions: { headers: csrfHeaders(form) },
    });
    handleSuccess(form, "login");
  } finally {
    if (conditionalControllers.get(form) === controller) {
      conditionalControllers.delete(form);
    }
  }
}

async function submitRegister(form) {
  const registrationKind = form.dataset.registrationKind;
  const capability = form.dataset.capability;
  if (registrationKind && capability) {
    await registerPasskey({
      optionsUrl: form.dataset.optionsUrl,
      verifyUrl: form.dataset.verifyUrl,
      optionsBody: { registration_kind: registrationKind, capability },
      fetchOptions: { headers: csrfHeaders(form) },
    });
    handleSuccess(form, "register");
    return;
  }
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

async function submitPasskeyForm(form, hint) {
  if (!assertWebAuthnSupport(form)) return;
  const action = form.dataset.passkeyForm;
  setStatus(
    form,
    hint === "hybrid" ? messages.js_hybrid_prompt : messages.js_waiting_prompt,
    "pending",
  );
  try {
    if (action === "register") {
      await submitRegister(form);
      return;
    }
    await submitLogin(form, hint);
  } catch (error) {
    setErrorUnlessAborted(form, error);
  }
}

async function credentialMutation(element, method, body) {
  const response = await fetch(element.dataset.url, {
    method,
    credentials: "same-origin",
    headers: { "content-type": "application/json", ...csrfHeaders(element) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.detail || messages.js_request_failed);
  }
  await response.text();
  window.location.reload();
}

function bindCredentialManagement(root) {
  root.querySelectorAll("[data-passkey-credential-label]").forEach((form) => {
    if (form.dataset.passkeyBound === "true") return;
    form.dataset.passkeyBound = "true";
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        await credentialMutation(form, "POST", {
          label: form.elements.namedItem("label").value,
        });
      } catch (error) {
        setStatus(form, error instanceof Error ? error.message : messages.js_request_failed, "error");
      }
    });
  });
  root.querySelectorAll("[data-passkey-credential-remove]").forEach((button) => {
    if (button.dataset.passkeyBound === "true") return;
    button.dataset.passkeyBound = "true";
    button.addEventListener("click", async () => {
      if (!window.confirm(messages.confirm_credential_removal)) return;
      try {
        await credentialMutation(button, "DELETE");
      } catch (error) {
        const status = document.getElementById("passkey-credential-status");
        if (status) status.textContent = error instanceof Error ? error.message : messages.js_request_failed;
      }
    });
  });
}

async function startConditionalLogin(form) {
  if (
    form.dataset.passkeyForm !== "login" ||
    form.dataset.conditionalUi !== "true" ||
    !window.PublicKeyCredential?.isConditionalMediationAvailable
  ) return;
  if (!(await PublicKeyCredential.isConditionalMediationAvailable())) return;
  const controller = new AbortController();
  const previous = conditionalControllers.get(form);
  previous?.abort();
  conditionalControllers.set(form, controller);
  try {
    await loginPasskey({
      optionsUrl: form.dataset.optionsUrl,
      verifyUrl: form.dataset.verifyUrl,
      mediation: "conditional",
      signal: controller.signal,
      fetchOptions: { headers: csrfHeaders(form) },
    });
    handleSuccess(form, "login");
  } catch (error) {
    setErrorUnlessAborted(form, error);
  } finally {
    if (conditionalControllers.get(form) === controller) {
      conditionalControllers.delete(form);
    }
  }
}

function bindPasskeyForm(form) {
  if (form.dataset.passkeyBound === "true") return;
  form.dataset.passkeyBound = "true";
  assertWebAuthnSupport(form);
  void startConditionalLogin(form);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void submitPasskeyForm(form);
  });
  form.querySelector("[data-passkey-hybrid]")?.addEventListener("click", () => {
    void submitPasskeyForm(form, "hybrid");
  });
}

function bindAll(root = document) {
  bindCredentialManagement(root);
  if (root instanceof Element && root.matches("[data-passkey-form]")) {
    bindPasskeyForm(root);
  }
  for (const form of root.querySelectorAll("[data-passkey-form]")) {
    bindPasskeyForm(form);
  }
}

bindAll();
document.addEventListener("htmx:afterSwap", (event) => {
  bindAll(event.detail?.elt || document);
});
const removalObserver = new MutationObserver((mutations) => {
  for (const mutation of mutations) {
    for (const node of mutation.removedNodes) {
      if (node instanceof Element) {
        node.querySelectorAll("[data-passkey-form]").forEach(abortConditionalLogin);
        if (node.matches("[data-passkey-form]")) abortConditionalLogin(node);
      }
    }
  }
});
removalObserver.observe(document.documentElement, { childList: true, subtree: true });
