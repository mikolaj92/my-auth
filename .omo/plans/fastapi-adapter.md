---
status: ready-for-execution
slug: fastapi-adapter
created: 2026-06-24
source_draft: .omo/drafts/fastapi-adapter.md
scope: my-auth reusable FastAPI/Starlette passkey adapter
mode: executable-plan
---

# Plan: reusable FastAPI/Starlette adapter for `my-auth`

## Objective

Build a minimal reusable FastAPI/Starlette adapter in `my-auth` so projects such as `msds-portal/control-plane`, `rnkstr`, and `wolnyrolnik` can share the same passkey login flow instead of copying project-specific WebAuthn route code.

The adapter must standardize passkey ceremony routes and WebAuthn safety while leaving project-specific storage, sessions, templates, permissions, and migrations outside the core package.

## Hard constraints

- Do not change consuming projects in this plan. Implement adapter in `my-auth` only.
- Keep `import my_auth` free of FastAPI imports.
- `my_auth.fastapi` may require FastAPI/Starlette.
- Do not create a universal user DB schema or session backend.
- Keep credential persistence project-owned through the existing `CredentialStore` protocol.
- Preserve server-owned RP configuration through `PasskeyConfig`; never derive RP ID from client-provided origin.
- Strip legacy `response.userHandle` before login verification when configured, matching the verified MSDS migration behavior.
- Treat RNKSTR legacy `/start|finish` routes as project-local aliases, not core v1 adapter routes.
- Use TDD: write failing adapter tests before production adapter code.

## Inspection basis

### `my-auth`

Inspected:

- `pyproject.toml`
- `src/my_auth/__init__.py`
- `src/my_auth/passkeys.py`
- `src/my_auth/static/passkey.js`
- `tests/test_passkeys.py`
- `README.md`

Current core already owns:

- `PasskeyConfig`
- `PasskeyService`
- `MemoryChallengeStore`
- `CredentialStore`
- `PasskeyUser`
- `PasskeyCredential`
- `AuthenticationResult`
- vanilla JS helper

Current gap: no FastAPI router, no session adapter, no template adapter, no admin/permission policy, no universal DB schema.

Important behavior: `PasskeyService.finish_authentication(..., require_user_handle=False)` still rejects a mismatching non-null `response.userHandle`. The adapter must strip `response.userHandle` before delegating when legacy compatibility is enabled.

### MSDS `control-plane`

Verified first consumer. Shared route contract:

- `GET /login`
- `GET /register`
- `POST /api/auth/register/options`
- `POST /api/auth/register/verify`
- `POST /api/auth/login/options`
- `POST /api/auth/login/verify`
- `POST /logout`

Project-specific pieces that stay outside `my-auth`:

- SQLite credential adapter over `users` + `webauthn_credentials`
- DB session cookie `cp_session`
- admin/permission model
- Jinja templates and UI chrome
- credential delete/admin routes

Security lessons to encode in adapter tests/docs:

- server-owned `PasskeyConfig`
- strip legacy `response.userHandle` before verification when configured
- require real session users for protected project APIs
- ignored lockfiles are not reproducibility proof

### RNKSTR

Inspected FastAPI app with Starlette `SessionMiddleware`, async `aiosqlite`, and current direct WebAuthn.

Key facts:

- Current endpoints are `/api/auth/register/start`, `/api/auth/register/finish`, `/api/auth/login/start`, `/api/auth/login/finish`.
- Desired shared contract is the MSDS `/api/auth/*/options|verify` contract.
- Current auth derives RP ID from client-provided origin; adapter must prevent that by taking server-owned `PasskeyConfig`.
- Existing `users` table stores one credential directly on the user row (`credential_id`, `public_key`, `sign_count`).
- Admin policy is already project-owned via `require_admin(request, db)`.
- Some RNKSTR APIs still accept explicit `user_id`; adapter must not attempt to normalize app authorization.
- `templates/login.html` and `templates/register.html` were not found despite `app/main.py` rendering them; UI migration is project work.
- Debug `/api/auth/test` stays project-specific.

### WolnyRolnik

Inspected current Pocket ID OAuth app.

Key facts:

- Current auth stores a whole user object in `request.session["user"]`.
- `/login` is OAuth/dev-login entrypoint.
- `/auth/callback` stores `request.session["user"] = dict(user_info)` and upserts app `users` by `oidc_sub`.
- Protected routes use session dict fields such as `sub`, `email`, and `name`.
- DB is sync SQLAlchemy/raw SQL.
- `sql/schema.sql` has `users(id, email, name, oidc_sub, created_at, last_login)` and no passkey credential table.
- Templates are strict project-owned Basecoat/HTMX surfaces; adapter must not impose layout.
- Existing tests are public smoke tests only; project migration will need auth tests.

## Adapter contract

### Core routes

Default `PasskeyAuthRouter` routes:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/login` | Render project login page through hook. |
| `GET` | `/register` | Render project registration page through hook. |
| `POST` | `/api/auth/register/options` | Start registration ceremony. |
| `POST` | `/api/auth/register/verify` | Finish registration ceremony and log user in. |
| `POST` | `/api/auth/login/options` | Start discoverable-credential login ceremony. |
| `POST` | `/api/auth/login/verify` | Finish login ceremony and log user in. |
| `POST` | `/logout` | Run project logout hook and return configured response. |

RNKSTR `/start|finish` aliases are not core v1 routes. If needed, a consuming project adds temporary aliases locally that call the adapter routes or hooks.

### Public API shape

Add `src/my_auth/fastapi.py` exporting:

```python
AuthUser
PasskeyAuthRouter
PasskeyRouteHooks
PasskeyPaths
PasskeyCookies
```

Expected use:

```python
from my_auth import MemoryChallengeStore, PasskeyConfig, PasskeyService
from my_auth.fastapi import PasskeyAuthRouter, PasskeyRouteHooks

passkey_service = PasskeyService(
    config=PasskeyConfig(...),
    challenges=MemoryChallengeStore(),
    credentials=project_credential_store,
)

auth = PasskeyAuthRouter(
    service=passkey_service,
    hooks=PasskeyRouteHooks(...),
)
app.include_router(auth.router)
```

## Hook contract

Hooks must be sync-or-async. The adapter awaits each hook via an internal `maybe_await` helper.

### `AuthUser`

Adapter-facing dataclass/protocol:

```python
AuthUser(
    user_id: str,
    user_handle: bytes,
    name: str,
    display_name: str | None = None,
    raw: object | None = None,
)
```

The adapter converts `AuthUser` to `PasskeyUser` for registration and authentication. It never dictates how the project serializes sessions.

### Required hooks

`PasskeyRouteHooks` must require:

- `get_session_user(request) -> AuthUser | None`
- `make_registration_user(request, display_name: str) -> AuthUser | PasskeyUser`
- `get_auth_user(user_id: str) -> AuthUser | None`
- `login(response, request, user: AuthUser) -> None`
- `logout(response, request) -> None`
- `registration_allowed(request) -> bool | None`
- `render_login(request) -> Response`
- `render_register(request, *, bootstrap: bool) -> Response`

### Optional hooks

- `after_register(request, user, credential) -> None`
- `after_login(request, user, credential) -> None`
- `on_auth_error(request, exc) -> Response | None`

### Hook ordering guarantees

Registration verify order:

1. Parse request body.
2. Pop/verify challenge through `PasskeyService.finish_registration`.
3. Resolve `AuthUser` via session user or `get_auth_user(passkey.user_id)`.
4. Call `login(response, request, user)`.
5. Call `after_register(...)` if provided.
6. Delete challenge/register cookies.
7. Return response.

Login verify order:

1. Parse request body.
2. If legacy stripping is enabled, remove `response.userHandle` from parsed payload.
3. Pop/verify challenge through `PasskeyService.finish_authentication`.
4. Resolve `AuthUser` with `get_auth_user(result.user.user_id)`.
5. Call `login(response, request, user)`.
6. Call `after_login(...)` if provided.
7. Delete challenge cookie.
8. Return response.

`login`, `after_login`, and `after_register` must run only after successful WebAuthn verification. If verification fails, session hooks must not run.

## Cookie and challenge behavior

Default `PasskeyCookies`:

- challenge cookie name: `passkey_challenge`
- registration display-name cookie name: `passkey_register_name`
- `path="/"`
- `httponly=True`
- `samesite="lax"`
- `secure` configurable; default `True` when `config.origin` is HTTPS, `False` for localhost HTTP
- `max_age=config.challenge_ttl_seconds`

Cookie behavior:

- options endpoints set challenge cookie.
- register options also sets registration display-name cookie only if needed by project hooks.
- verify endpoints delete challenge cookie on success.
- registration verify deletes registration display-name cookie on success.
- logout calls project `logout` hook and deletes adapter challenge cookies.
- failed verification should pop the challenge when `PasskeyService` pops it; replay must fail.
- process restart with `MemoryChallengeStore` loses outstanding challenges; user must retry. Persistent challenge store is an injection point, not v1 default.

## Endpoint request/response details

### `POST /api/auth/register/options`

Request JSON:

```json
{"display_name": "Alice"}
```

Behavior:

- `display_name` required and non-empty.
- call `registration_allowed(request)`; if false, return `403`.
- choose existing session user for add-passkey, otherwise `make_registration_user`.
- call `service.begin_registration(flow_id, passkey_user)`.
- return WebAuthn options JSON with status `200` and content type `application/json`.
- set challenge cookie.

### `POST /api/auth/register/verify`

Request JSON: browser credential object from `navigator.credentials.create`.

Behavior:

- require challenge cookie; missing => `400`.
- call `service.finish_registration`.
- resolve `AuthUser` and call `login` hook.
- return `{"ok": true}` by default, with status `200`.
- delete challenge/registration cookies.

### `POST /api/auth/login/options`

Request JSON: `{}` by default.

Behavior:

- call `service.begin_authentication(flow_id)` for discoverable login.
- return WebAuthn options JSON with status `200`.
- set challenge cookie.

### `POST /api/auth/login/verify`

Request JSON: browser credential object from `navigator.credentials.get`.

Behavior:

- require challenge cookie; missing => `400`.
- parse JSON before delegating.
- if `strip_legacy_user_handle=True`, remove `response.userHandle`.
- call `service.finish_authentication(..., require_user_handle=not strip_legacy_user_handle)` or equivalent explicit option.
- resolve `AuthUser` and call `login` hook.
- return `{"ok": true}` by default, with status `200`.
- delete challenge cookie.

### `POST /logout`

Behavior:

- call `logout(response, request)` hook.
- delete adapter challenge cookies.
- return redirect configured by paths/hooks, default `303` to `/login` or `/` as configured.

## Dependency and packaging plan

Modify `pyproject.toml`:

- keep core dependency list unchanged except as needed for packaging metadata.
- add optional extra:

```toml
[project.optional-dependencies]
fastapi = ["fastapi>=0.115"]
```

- add dev dependencies for tests:

```toml
[dependency-groups]
dev = [
  "pytest>=8",
  "fastapi>=0.115",
  "httpx>=0.27",
]
```

If current project tooling requires a different uv-compatible dev dependency shape, preserve existing style and add only the minimal test dependencies.

`src/my_auth/__init__.py` should not import FastAPI adapter. Keep adapter import explicit: `from my_auth.fastapi import ...`.

## JS helper plan

Update `src/my_auth/static/passkey.js` defaults to match the adapter contract:

- `/api/auth/register/options`
- `/api/auth/register/verify`
- `/api/auth/login/options`
- `/api/auth/login/verify`

Keep caller override support for custom paths.

## Implementation waves

### Wave 1 — adapter tests first

Create `tests/test_fastapi_adapter.py` with failing tests using FastAPI `TestClient`, fake hooks, and a fake or memory credential store.

Required tests:

1. Router exposes standard endpoints.
2. `POST /api/auth/login/options` returns challenge JSON and sets challenge cookie with expected flags.
3. `POST /api/auth/login/verify` strips legacy `response.userHandle` before delegating to service.
4. Verify replay fails after challenge is consumed.
5. Challenge expiry returns a 400-style auth error.
6. Async hooks are awaited and run in correct order.
7. Registration policy denial returns 403 and does not create a challenge.
8. Register options/verify call `make_registration_user`, `finish_registration`, `login`, and optional `after_register` in order.
9. `login` and `after_login` hooks do not run when WebAuthn verification fails.
10. Logout calls project `logout` hook, deletes adapter cookies, and returns configured redirect.
11. JS helper defaults point at `/api/auth/...` endpoints.
12. Adapter phase does not create project schema/session/template migration helpers.

### Wave 2 — minimal adapter module

Create `src/my_auth/fastapi.py`.

Implement:

- `AuthUser`
- `PasskeyPaths`
- `PasskeyCookies`
- `PasskeyRouteHooks`
- `PasskeyAuthRouter`
- `_maybe_await`
- internal request parsing helpers
- internal cookie helpers
- default error handling

Use `APIRouter`; keep handlers thin.

### Wave 3 — JS helper and docs

Update `src/my_auth/static/passkey.js` endpoint defaults.

Update `README.md`:

- keep core-only explanation
- add FastAPI adapter section
- show minimal hook example
- state project-owned responsibilities
- document endpoint contract
- document legacy `userHandle` stripping option
- document memory challenge store limitation
- document RNKSTR aliases as project-local migration option

### Wave 4 — verification

Run in `/Users/mini-m4-main/Developer/my-auth`:

```bash
uv run pytest
```

Also run import checks:

```bash
uv run python -c "import my_auth; print('core ok')"
uv run python -c "from my_auth.fastapi import PasskeyAuthRouter; print(PasskeyAuthRouter.__name__)"
```

No browser is required for this adapter phase; TestClient covers the FastAPI surface and JS defaults test covers helper endpoint paths.

## Success criteria for implementation

- `my_auth.fastapi` provides reusable FastAPI/Starlette passkey routes with the standard endpoint contract.
- Core `import my_auth` remains FastAPI-free.
- Adapter tests prove cookie behavior, challenge replay/expiry, async hook support, hook ordering, registration denial, logout, legacy `userHandle` stripping, and JS endpoint defaults.
- README explains how MSDS, RNKSTR, and WolnyRolnik plug in through hooks/stores without adapter owning their DB/session/templates.
- `uv run pytest` passes.

## Out of scope for this adapter implementation

- Migrating RNKSTR to the adapter.
- Migrating WolnyRolnik to passkeys.
- Reworking MSDS integration to consume the adapter.
- Creating universal DB migrations.
- Creating a universal admin/permissions layer.
- Designing project-specific login/register UI.
- Removing Pocket ID from WolnyRolnik.

Those should be separate follow-up plans after the adapter exists.

## Follow-up project plans after adapter ships

1. MSDS cleanup: replace local `auth_routes.py` ceremony code with `PasskeyAuthRouter` hooks.
2. RNKSTR migration: add `my-auth`, replace direct WebAuthn auth router, decide whether to keep `/start|finish` aliases temporarily, add or adapt credential storage.
3. WolnyRolnik migration: add passkey credential storage and hooks that create the existing `request.session["user"]` shape while coexisting with or replacing Pocket ID.
