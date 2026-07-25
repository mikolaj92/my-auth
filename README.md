# my-auth

`my-auth` is a passkey-only authentication core for FastAPI/Starlette
applications. Version 0.2 uses verification-first registration and explicit,
versioned SQLite schema ownership.

The package provides RP configuration, WebAuthn options and verification,
single-use TTL challenges, passkey models, atomic credential registration,
compare-and-set sign counters, and optional FastAPI/Jinja/HTMX adapters. It
does **not** provide application sessions, CSRF middleware, admin policy, local
user models, or audit policy.

## Install and imports

```sh
uv add "my-auth @ git+https://github.com/mikolaj92/my-auth.git"
uv add "my-auth[fastapi] @ git+https://github.com/mikolaj92/my-auth.git"
uv add "my-auth[fastapi-htmx] @ git+https://github.com/mikolaj92/my-auth.git"
```

The core import is `my_auth`. The FastAPI router is explicitly imported from
`my_auth.fastapi`; the server-rendered UI is explicitly imported from
`my_auth.fastapi_htmx`. Optional imports are not performed by `import my_auth`.

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

The current schema version is `2`. `ensure_sqlite_schema` creates/stamps an
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
- `prepare_registration(request, display_name)` — pure policy/profile step;
- `complete_registration(request, verified)` — durable host completion, returning
  an `AuthUser` or `None`;
- `get_auth_user(user_id)`, `login(response, request, user)`, `logout(response, request)`;
- `registration_allowed(request)`, `render_login(request)`, and
  `render_register(request, *, bootstrap)`.

Every callback may be synchronous or asynchronous. The router awaits either
form. Registration policy is checked before options and again before verify;
then the router verifies, calls durable completion, logs the user in, and calls
`after_register` as an observer. A `None` completion denies registration and
prevents login. Observer failures are logged and do not turn an otherwise
successful login or registration into a 500. Login and registration use
separate challenge cookies: `passkey_authentication_challenge` and
`passkey_registration_challenge`. These are WebAuthn flow cookies, not app
sessions. CSRF middleware is intentionally absent; the host applies its CSRF
policy.

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
    registration_allowed=registration_allowed,
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

`PasskeyFastAPISettings.from_env()` requires `PASSKEY_RP_ID`,
`PASSKEY_RP_NAME`, and `PASSKEY_ORIGIN`; it also supports the documented
`PASSKEY_*` timeout, verification, path, and cookie settings. The default
routes are `GET /login`, `GET /register`, `POST /logout`, and JSON
`POST /api/auth/{login,register}/{options,verify}`.

The `fastapi-htmx` adapter installs the same app-factory shell used by the host,
wraps the existing passkey router, and owns its package static mount. It does
not change WebAuthn verification, registration ordering, or transaction semantics:

```python
from app_factory.fastapi import install_app_factory_ui
from my_auth.fastapi_htmx import PasskeyUiConfig, install_passkey_ui

platform = install_app_factory_ui(app, environments=[])
install_passkey_ui(
    app,
    platform=platform,
    service=passkeys,
    hooks=hooks,
    config=PasskeyUiConfig(),
)
```

The host installs the shared platform first and passes its typed `AppFactoryUi`
value to the adapter. The installer is idempotent for the same platform and
configuration, and rejects conflicting setup; hosts do not manually include
the router or mount package static files.

## Ownership matrix

| Concern | Owner |
| --- | --- |
| RP configuration, WebAuthn verification, challenge consumption | `my-auth` |
| Passkey tables and auth schema version/migration | `my-auth` (or the shared `SQLiteAuthDatabase` owner) |
| Local users, external identity links, roles, grants, audit rows | host / `my-usermanager` |
| Application sessions, app cookies, CSRF, logout effects | host application |
| Registration policy and local provisioning | host callback |
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
Keep `rp_id` and `origin` server-configured, use Secure/HttpOnly/SameSite flow
cookies, rotate or clear the host session on login, and protect state-changing
routes with host CSRF controls. WebAuthn browsers without support need a
host-provided recovery or fallback path.
