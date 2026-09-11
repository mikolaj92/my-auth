# my-auth

[Security policy](SECURITY.md) · [Changelog](CHANGELOG.md) · [OIDC provider profile](docs/oidc-provider.md)

**Product identity:** my-auth is a minimal OpenID Provider. A generic relying
party talks to it through discovery, authorization-code + S256 PKCE, JWKS, and
UserInfo, then can swap the issuer for another OP without rewriting the app.
Passkeys stay behind that protocol. The profile is the `my-auth[oidc]` extra;
see the linked support matrix. This is not OpenID Foundation certification.

`my-auth` is also a passkey-only WebAuthn RP for FastAPI/Starlette applications.
Version 0.5 uses verification-first, neutral multi-user registration and
explicit, versioned SQLite schema ownership. Enrollment exposure and grants
belong to each host application.

The package provides RP configuration, WebAuthn options and verification,
single-use TTL challenges, passkey models, atomic credential registration,
compare-and-set sign counters, and optional FastAPI/Jinja/HTMX adapters. It
does **not** provide application sessions, CSRF middleware, admin policy, local
user models, or audit policy.

## Install and imports

```sh
uv add "my-auth @ git+https://github.com/mikolaj92/my-auth.git@v0.5.6"
uv add "my-auth[oidc] @ git+https://github.com/mikolaj92/my-auth.git@v0.5.6"
uv add "my-auth[fastapi-htmx] @ git+https://github.com/mikolaj92/my-auth.git@v0.5.6"
```

Pin the immutable 0.5.x tag selected by the platform BOM. Hosts should use
`my-auth>=0.5,<0.6` and must not mix incompatible identity generations.
The OpenID Provider extra is `my-auth[oidc]`; `my-auth[fastapi]` remains an
identical compatibility alias. `PasskeyRouteHooks.rate_limit`,
`PASSKEY_ORIGINS`, and `PasskeyUiConfig(conditional_ui=True)` are in this tag.

This repository uses app-factory tag `v0.7.2` to test the optional HTMX
adapter. It is a library, not a production host using `app-factory[platform]`,
so the [platform host compatibility matrix](https://github.com/mikolaj92/app-factory/blob/v0.7.2/COMPAT.md)
does not define this package's version. The published `fastapi-htmx` extra
requires the compatible `app-factory>=0.7.2` generation.

The core import is `my_auth`. The FastAPI router is explicitly imported from
`my_auth.fastapi`; the server-rendered UI is explicitly imported from
`my_auth.fastapi_htmx`. The optional OIDC protocol router is imported from
`my_auth.oidc_fastapi` and requires the `oidc` extra. Optional framework imports
are not performed by `import my_auth`.

## Optional OIDC Provider

The shipped OIDC profile is a minimal OpenID Provider in the same FastAPI app.
Passkeys stay on `/login` behind authorize. The app is also the relying party at
`/oidc/callback` on that origin. No second server is required. It supports public
clients, exact HTTPS redirects, S256 PKCE, RS256 ID tokens, public JWKS, scoped
UserInfo, short-lived one-time codes, and opaque bearer access tokens. Discovery
advertises `claims_supported` and the implemented code+S256 surface so a generic
relying party can pin this issuer and later swap it for another OpenID Provider.
Refresh tokens, implicit/hybrid/password grants, dynamic registration, and logout
extensions are not advertised or implemented by this profile.

Install the optional adapter with `my-auth[oidc]` and configure a durable
`SigningKeyStore` in production. `MemorySigningKeyStore` is for tests and
examples only:

```python
from my_auth import OIDCClient, OIDCProvider, OIDCProviderConfig
from my_auth.oidc_fastapi import (
    MemorySigningKeyStore,
    OIDCProviderHooks,
    build_oidc_fastapi_plugin,
)

provider = OIDCProvider(
    OIDCProviderConfig(
        issuer="https://app.example.test",
        authorization_endpoint="https://app.example.test/oauth/authorize",
        token_endpoint="https://app.example.test/oauth/token",
        jwks_uri="https://app.example.test/oauth/jwks",
        userinfo_endpoint="https://app.example.test/oauth/userinfo",
    ),
    clients=(
        OIDCClient(
            client_id="product",
            redirect_uris=("https://app.example.test/oidc/callback",),
            scopes=("openid", "profile", "email"),
        ),
    ),
    signing_keys=MemorySigningKeyStore.generate(),
)
hooks = OIDCProviderHooks(
    get_session_user=get_session_user,
    decide_consent=decide_consent,
    login_url="/login",
)
app.include_router(build_oidc_fastapi_plugin(provider=provider, hooks=hooks))
```

`OIDCProviderHooks.get_session_user`, `decide_consent`, and optional `login_url`
remain host policy seams. `login_url` must be an application-relative path on
this origin; unauthenticated authorize redirects there with `next` pointing back
at `/oauth/authorize`. The host maps stable local subjects and claims through
`OIDCUserAdapter`, owns `/oidc/callback` as the relying party, enforces
disabled-account behavior, and protects the provider with its deployment/session
controls. See
[`docs/oidc-provider.md`](docs/oidc-provider.md) for the support matrix and
conformance gates; passing the included integration tests is not certification.

## Store transaction contract

Hosts do not need to copy our SQLite transaction tests:

```python
from my_auth import SQLiteCredentialStore, ensure_sqlite_schema
from my_auth.testing import assert_external_transaction_contract

assert_external_transaction_contract(
    lambda connection: SQLiteCredentialStore(connection, transaction_mode="external"),
    ensure_sqlite_schema,
)
```

This helper owns a disposable in-memory **SQLite** connection and passes an
active transaction to the store factory. It checks a shared host record and
passkey registration commit together; a forced host failure rolls back both the
credential and user/handle records. Hidden commits fail the contract. It is not
a portable transaction API: non-SQLite backends must use their own transaction
harness, and memory stores cannot claim transactional compliance through a skip.
Existing credential/challenge, CAS, ownership and idempotency tests still apply.

## Core lifecycle and registration ordering

```python
from my_auth import MemoryChallengeStore, PasskeyConfig, PasskeyService

passkeys = PasskeyService(
    config=PasskeyConfig(
        rp_id="example.com", rp_name="Example", origin="https://example.com"
    ),
    challenges=MemoryChallengeStore(),
    credentials=credentials,
)
```

`begin_registration(flow_id=..., user=...)` creates options and stores a
registration challenge. It performs no durable user or credential write.
`verify_registration(flow_id=..., credential=...)` consumes the one-time
challenge, verifies WebAuthn, and returns `VerifiedRegistration`; it also does
not write durable records. The host then calls
`CredentialStore.save_registration(result)` (or an equivalent shared
transaction) **after** successful verification. Failed options or verification
never reach durable registration.

`save_registration` is atomic and idempotent for identical immutable data.
Ownership conflicts raise `PasskeyUserConflict` or
`PasskeyCredentialConflict`; records are never reassigned. Login updates use
`compare_and_set_credential_after_login`. A stale non-zero expected counter
raises `CredentialCounterConflict`; zero-counter authenticators retain
zero-to-zero behavior.

## SQLite schema lifecycle

There is one database owner per logical product/RP. `my-auth` owns its
`passkey_users`, `passkey_credentials`, `passkey_challenges`, and
`my_auth_schema` tables. Host domain tables and application sessions remain
host-owned. A product composing `my-auth` with `my-usermanager` should use
`my_usermanager.adapters.my_auth_sqlite.SQLiteAuthDatabase` as the one shared
owner rather than constructing independent databases.

Inspection is separate from mutation. Stores never create a schema
implicitly: inspect first, then explicitly initialize or migrate before
constructing stores.

```python
import sqlite3
from my_auth import ensure_sqlite_schema, inspect_sqlite_schema, migrate_sqlite_schema

with sqlite3.connect("app.sqlite3") as connection:
    state = inspect_sqlite_schema(connection)
    if state.state in {"empty", "canonical_unversioned"}:
        ensure_sqlite_schema(connection)
    elif state.state == "legacy":
        migrate_sqlite_schema(connection)
    elif state.state != "current":
        raise RuntimeError("unsupported schema: " + "; ".join(state.diagnostics))
```

The current schema version is `3`. `ensure_sqlite_schema` creates/stamps an
empty or canonical-unversioned schema and is idempotent; it never migrates a
legacy layout. `migrate_sqlite_schema` migrates the supported 0.1 layout
atomically, including the legacy `flow_key` challenge column, and rolls back
on failure. Both operations require a connection with no pending transaction;
unsupported layouts are refused. `sqlite_schema_sql()` returns the canonical
DDL.

Path-mode `SQLiteCredentialStore` and `SQLiteChallengeStore` open a short-lived
connection per operation and reject path-mode `:memory:`. A caller-owned
`sqlite3.Connection` is never closed. `transaction_mode="operation"` commits
that store operation independently; `transaction_mode="external"` uses a
savepoint and leaves commit/rollback to the caller. Do not use private store
connections to join a transaction. SQLite connections are thread-affine by
default: use one connection per thread, or deliberately configure and
coordinate a shared connection; path-mode stores avoid this issue by opening
per operation.

## FastAPI adapter

`PasskeyRouteHooks` requires these callbacks:

- `get_session_user(request)` — current host session user, or `None`;
- `prepare_registration(request, username)` — legacy-compatible neutral
  self-registration subject preparation;
- `prepare_registration_context(request, flow_id, username)` — preferred typed
  resolver for neutral self-registration; it must resolve one concrete
  `PasskeyUser` and may apply the host's enrollment rules before returning;
- `complete_registration(request, verified)` — durable host completion, returning
  an `AuthUser` or `None`;
- `get_auth_user(user_id)`, `login(response, request, user)`,
  `logout(response, request)`, `render_login(request)`, and
  `render_register(request)`.

Authenticated registration is always typed as `additional_credential` and
gets its subject only from `get_session_user`; request identity fields cannot
retarget it. Anonymous typed resolvers return a subject-bound
`RegistrationContext(kind="self_registration", ...)`. Invitation and recovery
contexts require a capability id and can be constructed with
`registration_context_from_capability(...)`, which validates capability purpose
and subject. Configure `prepare_capability_registration_context(request,
flow_id, kind, capability)` to claim the opaque token for that flow.

The host owns enrollment policy. It decides whether to expose, hide, protect,
or redirect a registration route and rejects enrollment before returning a
registration context. `my-auth` does not model open/closed registration, a
first user, or administrator bootstrap. Its router only performs a ceremony for
the explicit subject/context prepared by the host.

The shared HTMX adapter exposes distinct `PasskeyPaths.activation_page`
(`/activate`) and `recovery_page` (`/recover`) surfaces. They submit only the
opaque capability and flow kind, render the same non-enumerating invalid state
for missing or unusable links, and support locale plus separate
activation/recovery success URLs. The resolved context is persisted with the
WebAuthn challenge and returned unchanged in `VerifiedRegistration.context`.
The legacy `prepare_registration` path maps to neutral `self_registration`.

Every callback may be synchronous or asynchronous. The router awaits either
form. It verifies, calls durable completion, logs the user in, and calls
`after_register` as an observer. A `None` completion denies registration and
prevents login. Observer failures are logged and do not turn an otherwise
successful login or registration into a 500. Login and registration use
separate challenge cookies: `passkey_authentication_challenge` and
`passkey_registration_challenge`. These are WebAuthn flow cookies, not app
sessions. CSRF middleware is intentionally absent; the host applies its CSRF
policy.

The optional
`PasskeyRouteHooks.rate_limit(request, operation)` hook runs before
options creation or verification. It returns `RateLimitDecision.allow()` or
`RateLimitDecision.deny(retry_after_seconds=...)`; denial returns a neutral 429
with `Retry-After` when supplied and creates/consumes no challenge. A limiter
exception or malformed decision fails closed with a neutral 503. The four
operation names are `login_options`, `login_verify`, `register_options`, and
`register_verify`. The host owns the key (for example, a trusted
proxy-derived network key plus operation and a documented user scope), proxy
trust, limits, and shared storage. The hook must not trust arbitrary
`X-Forwarded-For`, use only a random flow id, or turn a transient limiter
failure into an allow. Path-local memory is not a multi-worker guarantee;
production deployments need a deliberately shared limiter where required.

```python
from my_auth.fastapi import (
    PasskeyFastAPIHooks,
    PasskeyFastAPISettings,
    build_passkey_fastapi_plugin,
)

hooks = PasskeyFastAPIHooks(
    get_session_user=get_session_user,
    prepare_registration=prepare_registration,
    complete_registration=complete_registration,
    get_auth_user=get_auth_user,
    login=login,
    logout=logout,
    render_login=render_login,
    render_register=render_register,
)
app.include_router(
    build_passkey_fastapi_plugin(
        settings=PasskeyFastAPISettings.from_env(),
        credentials=credentials,
        challenges=challenges,
        hooks=hooks,
    )
)
```

`PasskeyFastAPISettings.from_env()` requires `PASSKEY_RP_ID`, `PASSKEY_RP_NAME`,
and either `PASSKEY_ORIGINS` (comma-separated) or the legacy `PASSKEY_ORIGIN`;
it also supports the documented `PASSKEY_*` timeout, verification, path, and
cookie settings. The default
routes are `GET /login`, `GET /register`, `POST /logout`, and JSON
`POST /api/auth/{login,register}/{options,verify}`.

The `fastapi-htmx` extra is composed by the host through app-factory, not by
calling this package's installer. Hosts use `PasskeyBinding` plus
`install_identity_adapters` from `app_factory.adapters`. That composer installs
the shared platform chrome, wraps the passkey router, and mounts package static
files. It does not change WebAuthn verification, registration ordering, or
transaction semantics:

```python
from app_factory.adapters import PasskeyBinding, install_identity_adapters
from app_factory.platform import PlatformConfig

install_identity_adapters(
    app,
    environments=[templates.env],
    config=PlatformConfig(),
    passkey=PasskeyBinding(service=passkeys, hooks=hooks),
)
```

Hosts supply persistence, session transport (`login` / `logout` /
`get_session_user`), and enrollment policy. They do **not** call
`install_passkey_ui` or `install_app_factory_ui`, do not construct
`PasskeyUiConfig`, and do not copy installer or render glue. Dummy
`render_login` / `render_register` callables are not a host concern; packaged
templates own those slots.

The composer is idempotent for the same chrome and adapter selection, and
rejects conflicting setup. Hosts do not manually include the router or mount
package static files.

Internal adapter API / library tests only: `install_passkey_ui` remains a
package function used by the app-factory adapter. It is not a host recipe.

Authenticated credential management is available at `GET /account/passkeys`.
The shared page lists only credentials owned by `get_session_user`, links to the
existing session-derived additional-credential registration, and exposes
owner-scoped label and removal actions. Removal preserves the final credential
atomically by default. A host may provide `allow_final_credential_removal` only
when its explicit recovery policy makes credentialless account state safe.
Labels are trimmed and limited to 80 characters; credential public keys and
other sensitive registration data are never rendered.

## Ownership matrix

| Concern | Owner |
| --- | --- |
| RP configuration, WebAuthn verification, challenge consumption | `my-auth` |
| Passkey tables and auth schema version/migration | `my-auth` (or the shared `SQLiteAuthDatabase` owner) |
| Local users, external identity links, roles, grants, audit rows | host / `my-usermanager` |
| Application sessions, app cookies, CSRF, logout effects | host application |
| Enrollment routing, policy, and local provisioning | host / user-management layer |
| Atomic verified registration across passkey + UM records | shared transaction owner |
| Observer side effects (`after_register`, `after_login`) | host callback; failures are non-fatal |

## 0.1 to 0.2 mapping

| 0.1 API or behavior | 0.2 API or behavior |
| --- | --- |
| `PasskeyRouteHooks.make_registration_user` | `prepare_registration` for pure preparation, followed by `complete_registration` after verification |
| `PasskeyService.finish_registration` | `PasskeyService.verify_registration`, returning `VerifiedRegistration` without a durable write |
| One shared `PasskeyCookies.challenge` | Separate `PasskeyCookies.authentication_challenge` and `registration_challenge` |
| `PasskeyCookies.register_name` | Removed; the registration challenge stores the prepared user |
| Implicit schema creation in SQLite stores | Removed; call `inspect_sqlite_schema`, then `ensure_sqlite_schema` or `migrate_sqlite_schema` |
| Unversioned canonical schema / `flow_key` challenge column | Version 2 schema with `my_auth_schema` and `key`; migrate supported legacy layouts explicitly |
| Independent store commits for a cross-product registration | `transaction_mode="external"` stores inside the caller-owned shared transaction |
| Host completion after the router's credential lookup | Completion receives verified registration and is the durable registration boundary |

## Security and browser requirements

Use HTTPS in production; `http://localhost` is allowed for local development.
Each configured origin is an exact browser origin; its port is part of that
origin. Keep `rp_id` and `origins` server-configured, use Secure/HttpOnly/SameSite flow
cookies, rotate or clear the host session on login, and protect state-changing
routes with host CSRF controls. The legacy `origin="https://..."`
constructor and `PASSKEY_ORIGIN` environment variable map to a one-origin
allowlist; new hosts should use `origins=(...)` and `PASSKEY_ORIGINS`
(comma-separated). Do not provide both forms. This server-side allowlist is
unrelated to WebAuthn Related Origin Requests: any `.well-known/webauthn` file
and its hosting are owned by the host, and unrelated web domains or Android
origins are not automatically trusted. The optional login Conditional UI uses a
visible `autocomplete="username webauthn"` field and only starts after
`PublicKeyCredential.isConditionalMediationAvailable()` reports support; the
manual and hybrid buttons remain the fallback. It is disabled by default for
existing hosts; enable it with `PasskeyUiConfig(conditional_ui=True)`. Browsers
without WebAuthn need a host-provided recovery or fallback path.
