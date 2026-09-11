# Changelog

Entries describe source changes. A Git tag is not necessarily a published
[GitHub Release](https://github.com/mikolaj92/my-auth/releases).
The tested cross-library pins live only in the
[app-factory compatibility matrix](https://github.com/mikolaj92/app-factory/blob/main/COMPAT.md).

## Unreleased

- After a passkey, login returns to a same-origin `next` from authorize
  (`/oauth/authorize?...`). Off-origin `next` values are ignored. The page no
  longer mentions JSON API responses.

- Prove the advertised OpenID profile at the HTTP seam: ID tokens carry `iat`,
  `auth_time`, and `at_hash`; confidential clients redeem codes with
  `client_secret_basic`; consent denial returns `access_denied` to the client;
  token responses send `Cache-Control: no-store`; UserInfo accepts a Bearer
  token in the POST body; 401 UserInfo advertises RFC 6750
  `WWW-Authenticate: Bearer error="..."`.

- One FastAPI app is both the minimal OpenID Provider and the relying party:
  unauthenticated authorize redirects to a same-origin `login_url` with `next`;
  `prompt=none` still returns `login_required` to the client. No second server.

- State the product identity as a minimal, pluggable OpenID Provider: a generic
  relying party pins discovery/authorize/token/JWKS/UserInfo and can later swap
  the issuer. Refresh tokens, logout extensions, and OpenID Foundation
  certification stay out of this profile, not as unfinished protocol work.

- Advertise OpenID Discovery fields required by a generic relying party:
  `claims_supported`, `claim_types_supported`, and explicit
  `request_parameter_supported` / `request_uri_parameter_supported` false.
  A standard RP can complete authorization-code + S256 PKCE from discovery,
  JWKS, token, and UserInfo without my-auth-specific endpoints.

- Add opt-in WebAuthn Conditional UI/autofill on the login page with a visible
  `autocomplete="username webauthn"` field. Conditional mediation is feature-
  detected; manual and hybrid login remain available, and pending prompts are
  cancelled on manual login, HTMX replacement, and view removal (#105). The
  feature is disabled by default for existing hosts.

- Accept an explicit multi-origin WebAuthn allowlist through canonical
  `PasskeyConfig.origins` / `PASSKEY_ORIGINS`, while retaining the legacy
  single-origin constructor and environment aliases. Registration and
  authentication validate against the same exact allowlist; Related Origin
  Requests remain host-owned (#107).
- Add an optional pre-ceremony `PasskeyRouteHooks.rate_limit` seam with neutral
  429 responses, optional `Retry-After`, and no challenge mutation on denial.
  Limiter failures or malformed decisions fail closed with a neutral 503. Hosts
  retain ownership of keys, proxy trust, storage, and fail-closed policy (#108).
- Document the current SQLite schema version as `3`, matching
  `CURRENT_SCHEMA_VERSION` and `inspect_sqlite_schema().version` (#113).
- Mark `PasskeyRouteHooks.rate_limit`, `PASSKEY_ORIGINS`, and Conditional UI as
  unreleased after the pinned `v0.5.5` install tag (#114).
- Drop the npm Playwright toolchain; browser coverage uses the uv
  `playwright` extra.

`pyproject.toml` still reports `0.5.5` to match the pinned install tag. This
tree is not that tag.

## 0.5.5

- Add the optional Authlib/FastAPI OIDC Provider authorization-code profile with
  S256 PKCE, RS256 ID tokens, public JWKS, scoped UserInfo, and explicit host
  session/consent seams (#112). This is not an OpenID Foundation certification
  claim; consult `docs/oidc-provider.md` for unsupported features and gates.
- Require FastAPI >=0.141.1 in optional adapters and HTTPX2 >=2.12.0 for tests;
  verify the actual TestClient transport and error responses (#103).
- Align the nested app-factory source with the tested chrome generation (#95).
- Document host composition through `install_identity_adapters` (#96).
- Remove tracked automation leftovers (#97).
- Split passkey implementation into focused modules while retaining the facade (#98).
- Add private security reporting guidance and this source history (#104).
- Render passkey backup status badges without device-specific guarantees (#109).
- Expose `assert_external_transaction_contract` in `my_auth.testing` for external-mode stores (#111).

Source: [tag v0.5.5](https://github.com/mikolaj92/my-auth/tree/v0.5.5).

## 0.5.4

- Merge request-local platform context before rendering, avoiding duplicate
  keyword arguments when the host provides overlapping context.
- Update package and installation metadata.

Source: [tag v0.5.4](https://github.com/mikolaj92/my-auth/tree/v0.5.4).

## 0.5.3

- Align version and installation metadata after the request-local context work.

Source: [tag v0.5.3](https://github.com/mikolaj92/my-auth/tree/v0.5.3).

## 0.5.2

- Render packaged pages with request-local platform context.
- The v0.5.2 tag points to the rendering change; the subsequent commit named
  `Release my-auth v0.5.2` updates metadata and is included in later tags. Do not
  infer installed metadata from a release commit title alone.

Source: [tag v0.5.2](https://github.com/mikolaj92/my-auth/tree/v0.5.2).

## 0.5.1

- Correct package metadata to identify the neutral 0.5 API generation (#93).

Source: [tag v0.5.1](https://github.com/mikolaj92/my-auth/tree/v0.5.1).

## 0.5.0

- Remove first-administrator bootstrap and registration policy from the passkey
  library; hosts prepare explicit subjects and own enrollment policy (#91).
- Retain verification-first registration and typed subject-bound contexts.
- The preceding 0.4.8 release introduced WebAuthn 3; that dependency upgrade was
  not introduced by 0.5.0.

Source: [tag v0.5.0](https://github.com/mikolaj92/my-auth/tree/v0.5.0).
