const jsonHeaders = { "content-type": "application/json" };

function b64urlToBuffer(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(base64);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0)).buffer;
}

function bufferToB64url(value) {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function parseCreationOptions(options) {
  if (PublicKeyCredential.parseCreationOptionsFromJSON) return PublicKeyCredential.parseCreationOptionsFromJSON(options);
  return { ...options, challenge: b64urlToBuffer(options.challenge), user: { ...options.user, id: b64urlToBuffer(options.user.id) }, excludeCredentials: (options.excludeCredentials || []).map((credential) => ({ ...credential, id: b64urlToBuffer(credential.id) })) };
}

function parseRequestOptions(options) {
  if (PublicKeyCredential.parseRequestOptionsFromJSON) return PublicKeyCredential.parseRequestOptionsFromJSON(options);
  return { ...options, challenge: b64urlToBuffer(options.challenge), allowCredentials: (options.allowCredentials || []).map((credential) => ({ ...credential, id: b64urlToBuffer(credential.id) })) };
}

function serializeCredential(credential) {
  const response = credential.response;
  const out = { id: credential.id, rawId: bufferToB64url(credential.rawId), type: credential.type, response: {} };
  for (const key of ["clientDataJSON", "attestationObject", "authenticatorData", "signature", "userHandle"]) if (response[key]) out.response[key] = bufferToB64url(response[key]);
  if (typeof response.getTransports === "function") out.response.transports = response.getTransports();
  return out;
}

async function postJSON(url, body, fetchOptions = {}) {
  const response = await fetch(url, { method: "POST", credentials: "same-origin", ...fetchOptions, headers: { ...jsonHeaders, ...(fetchOptions.headers || {}) }, body: JSON.stringify(body) });
  if (!response.ok) throw new Error(`${url} failed: ${response.status}`);
  return response.json();
}

export async function registerPasskey({ optionsUrl = "/api/auth/register/options", verifyUrl = "/api/auth/register/verify", displayName, display_name, optionsBody = {}, fetchOptions = {} } = {}) {
  const body = { ...optionsBody };
  const name = display_name ?? displayName;
  if (name !== undefined) body.display_name = name;
  const options = await postJSON(optionsUrl, body, fetchOptions);
  const credential = await navigator.credentials.create({ publicKey: parseCreationOptions(options) });
  return postJSON(verifyUrl, serializeCredential(credential), fetchOptions);
}

export async function loginPasskey({ optionsUrl = "/api/auth/login/options", verifyUrl = "/api/auth/login/verify", fetchOptions = {} } = {}) {
  const options = await postJSON(optionsUrl, {}, fetchOptions);
  const credential = await navigator.credentials.get({ publicKey: parseRequestOptions(options) });
  return postJSON(verifyUrl, serializeCredential(credential), fetchOptions);
}

export const passkeyEncoding = { b64urlToBuffer, bufferToB64url };

const successMessages = { login: "Passkey sign-in succeeded.", register: "Passkey registration succeeded." };
function csrfHeaders(form) { const headerName = form.dataset.csrfHeader; const token = form.dataset.csrfToken; return headerName && token ? { [headerName]: token } : {}; }
function statusTarget(form) { const targetId = form.dataset.statusTarget; return targetId ? document.getElementById(targetId) : null; }
function setStatus(form, message, state) { const target = statusTarget(form); if (!target) return; target.dataset.state = state; target.textContent = message; }
function assertWebAuthnSupport(form) { if (window.PublicKeyCredential && navigator.credentials) return true; setStatus(form, "This browser does not support WebAuthn passkeys with PublicKeyCredential.", "error"); return false; }
function handleSuccess(form, action) { const successUrl = form.dataset.successUrl; if (successUrl) { window.location.assign(successUrl); return; } setStatus(form, successMessages[action], "success"); }
async function submitPasskeyForm(form) {
  if (!assertWebAuthnSupport(form)) return;
  setStatus(form, "Waiting for your passkey prompt.", "pending");
  try {
    const action = form.dataset.passkeyForm;
    if (action === "register") {
      const input = form.elements.namedItem("display_name");
      await registerPasskey({ optionsUrl: form.dataset.optionsUrl, verifyUrl: form.dataset.verifyUrl, displayName: input instanceof HTMLInputElement ? input.value : "", fetchOptions: { headers: csrfHeaders(form) } });
    } else await loginPasskey({ optionsUrl: form.dataset.optionsUrl, verifyUrl: form.dataset.verifyUrl, fetchOptions: { headers: csrfHeaders(form) } });
    handleSuccess(form, action);
  } catch (error) { setStatus(form, error instanceof Error ? error.message : "Passkey request failed.", "error"); }
}
for (const form of document.querySelectorAll("[data-passkey-form]")) { assertWebAuthnSupport(form); form.addEventListener("submit", (event) => { event.preventDefault(); void submitPasskeyForm(form); }); }
