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
  if (PublicKeyCredential.parseCreationOptionsFromJSON) {
    return PublicKeyCredential.parseCreationOptionsFromJSON(options);
  }
  return {
    ...options,
    challenge: b64urlToBuffer(options.challenge),
    user: { ...options.user, id: b64urlToBuffer(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((credential) => ({
      ...credential,
      id: b64urlToBuffer(credential.id),
    })),
  };
}

function parseRequestOptions(options) {
  if (PublicKeyCredential.parseRequestOptionsFromJSON) {
    return PublicKeyCredential.parseRequestOptionsFromJSON(options);
  }
  return {
    ...options,
    challenge: b64urlToBuffer(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((credential) => ({
      ...credential,
      id: b64urlToBuffer(credential.id),
    })),
  };
}

function serializeCredential(credential) {
  const response = credential.response;
  const out = {
    id: credential.id,
    rawId: bufferToB64url(credential.rawId),
    type: credential.type,
    response: {},
  };

  for (const key of ["clientDataJSON", "attestationObject", "authenticatorData", "signature", "userHandle"]) {
    if (response[key]) out.response[key] = bufferToB64url(response[key]);
  }
  if (typeof response.getTransports === "function") {
    out.response.transports = response.getTransports();
  }
  return out;
}

async function postJSON(url, body, fetchOptions = {}) {
  const response = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    ...fetchOptions,
    headers: { ...jsonHeaders, ...(fetchOptions.headers || {}) },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    const detail = typeof payload?.detail === "string" ? payload.detail : null;
    throw new Error(detail || `${url} failed: ${response.status}`);
  }
  return response.json();
}

export async function registerPasskey({
  optionsUrl = "/api/auth/register/options",
  verifyUrl = "/api/auth/register/verify",
  username,
  displayName,
  display_name,
  optionsBody = {},
  fetchOptions = {},
} = {}) {
  const registrationOptionsBody = { ...optionsBody };
  const capabilityFlow =
    registrationOptionsBody.registration_kind === "invitation" ||
    registrationOptionsBody.registration_kind === "recovery";
  const handle = typeof username === "string" ? username.trim() : "";
  if (!capabilityFlow && !handle) {
    throw new Error("Username is required.");
  }
  if (handle && /\s/.test(handle)) {
    throw new Error("Username must not contain spaces.");
  }
  if (handle) registrationOptionsBody.username = handle;
  // Optional display label only — never a substitute for username.
  const registrationDisplayName = display_name ?? displayName;
  if (registrationDisplayName !== undefined && registrationDisplayName !== "") {
    registrationOptionsBody.display_name = registrationDisplayName;
  }

  const options = await postJSON(optionsUrl, registrationOptionsBody, fetchOptions);
  const credential = await navigator.credentials.create({ publicKey: parseCreationOptions(options) });
  return postJSON(verifyUrl, serializeCredential(credential), fetchOptions);
}

export async function loginPasskey({
  optionsUrl = "/api/auth/login/options",
  verifyUrl = "/api/auth/login/verify",
  hint,
  fetchOptions = {},
} = {}) {
  const options = await postJSON(optionsUrl, {}, fetchOptions);
  if (hint) options.hints = [hint];
  const credential = await navigator.credentials.get({ publicKey: parseRequestOptions(options) });
  return postJSON(verifyUrl, serializeCredential(credential), fetchOptions);
}

export const passkeyEncoding = { b64urlToBuffer, bufferToB64url };
