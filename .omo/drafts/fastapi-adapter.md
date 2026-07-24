---
status: awaiting-approval
pending_action: write .omo/plans/fastapi-adapter.md
slug: fastapi-adapter
created: 2026-06-24
mode: planning-only
---

# my-auth FastAPI adapter — inspection draft

## Objective

Create one reusable FastAPI/Starlette adapter for `my-auth` so projects such as
`msds-portal/control-plane`, `rnkstr`, and `wolnyrolnik` can share the same
passkey login flow instead of copying project-specific WebAuthn route code.

This draft is **not implementation**. It records inspection findings and the
recommended plan direction. If approved, the next action is writing the final
execution plan at `.omo/plans/fastapi-adapter.md`.

## Inspected systems

### `my-auth` core

Files inspected:

- `/Users/mini-m4-main/Developer/my-auth/pyproject.toml`
- `/Users/mini-m4-main/Developer/my-auth/src/my_auth/__init__.py`
- `/Users/mini-m4-main/Developer/my-auth/src/my_auth/passkeys.py`
- `/Users/mini-m4-main/Developer/my-auth/src/my_auth/static/passkey.js`
- `/Users/mini-m4-main/Developer/my-auth/tests/test_passkeys.py`
- `/Users/mini-m4-main/Developer/my-auth/README.md`

Current reusable core already owns:

- `PasskeyConfig`: RP ID/name/origin, timeout, challenge TTL, user verification.
- `PasskeyService`: begin/finish registration and authentication ceremonies.
- `MemoryChallengeStore`: single-use TTL challenge storage.
- `CredentialStore` protocol: app-supplied user/credential persistence.
- `PasskeyUser`, `PasskeyCredential`, `AuthenticationResult` domain models.
- Vanilla JS helper in `static/passkey.js`.

Current deliberate gap: no FastAPI router, templates, session backend, admin
policy, or DB schema. `README.md` explicitly says v0 does not own those.

Important behavior to preserve: `finish_authentication(..., require_user_handle=False)`
still rejects a mismatching non-null `response.userHandle`. The verified MSDS
integration strips legacy `response.userHandle` before delegating to `my-auth`.

### MSDS `control-plane` — verified first consumer

Primary file inspected:

- `/Users/mini-m4-main/Developer/hermes-repos/msds-portal/control-plane/src/control_plane/web/auth_routes.py`

Verified shared route contract:

- `GET /login`
- `GET /register`
- `POST /api/auth/register/options`
- `POST /api/auth/register/verify`
- `POST /api/auth/login/options`
- `POST /api/auth/login/verify`
- `POST /logout`

MSDS-specific pieces that must remain outside `my-auth`:

- SQLite schema and adapter over `users` + `webauthn_credentials`.
- DB session cookie `cp_session`.
- Admin/permission model.
- Jinja templates and project UI.
- Credential delete/admin routes.

Security lessons from the verified integration:

- Keep RP config server-owned through `PasskeyConfig`; do not trust client origin
  for RP ID selection.
- Strip legacy `response.userHandle` before authentication verification when
  preserving old resident-key credentials.
- Require a real session user for auth/admin APIs; do not rely on fallbacks like
  dev-admin `get_current_user()`.
- Do not claim ignored lockfiles as tracked reproducibility evidence; pin package
  source revisions in tracked config.

### RNKSTR — second consumer

Files inspected:

- `/Users/mini-m4-main/Developer/rnkstr/requirements.txt`
- `/Users/mini-m4-main/Developer/rnkstr/README.md`
- `/Users/mini-m4-main/Developer/rnkstr/app/main.py`
- `/Users/mini-m4-main/Developer/rnkstr/app/auth.py`
- `/Users/mini-m4-main/Developer/rnkstr/app/auth_router.py`
- `/Users/mini-m4-main/Developer/rnkstr/app/database.py`
- `/Users/mini-m4-main/Developer/rnkstr/app/config.py`
- `/Users/mini-m4-main/Developer/rnkstr/app/admin.py`
- `/Users/mini-m4-main/Developer/rnkstr/app/users.py`
- `/Users/mini-m4-main/Developer/rnkstr/app/auth_test.py`
- `/Users/mini-m4-main/Developer/rnkstr/templates/base.html`
- `/Users/mini-m4-main/Developer/rnkstr/templates/components/sidebar.html`
- `/Users/mini-m4-main/Developer/rnkstr/templates/components/navigation.html`
- `/Users/mini-m4-main/Developer/rnkstr/tests/conftest.py`
- `/Users/mini-m4-main/Developer/rnkstr/tests/backend/test_main.py`

Findings:

- FastAPI + Starlette `SessionMiddleware` + `user_id` cookie fallback.
- Current direct WebAuthn endpoints are under `/api/auth/register/start`,
  `/api/auth/register/finish`, `/api/auth/login/start`, `/api/auth/login/finish`,
  not the desired MSDS contract.
- `app/auth.py` derives RP ID from a client-provided origin; the adapter must remove
  this pattern and use server-owned `PasskeyConfig`.
- `app/config.py` already has server-owned `RNKSTR_RP_ID`, `RNKSTR_RP_NAME`,
  `RNKSTR_ORIGIN`, and `RNKSTR_ALLOWED_ORIGINS`.
- `users` table stores one credential directly on the user row:
  `credential_id`, `public_key`, `sign_count`. This differs from MSDS's separate
  credentials table.
- DB access is async `aiosqlite`; MSDS is sync sqlite; WolnyRolnik is sync
  SQLAlchemy. The adapter must support async-capable hooks.
- `app/admin.py` already has a real-session admin dependency, so admin policy stays
  project-owned.
- Some APIs still accept explicit `user_id` params. The adapter should not try to
  normalize all project authorization.
- `templates/login.html` and `templates/register.html` were not found even though
  `app/main.py` renders them. Login UI is a project migration gap, not an adapter
  assumption.
- Debug login under `/api/auth/test` is project-specific and remains outside the
  adapter.

### WolnyRolnik — third consumer / variance check

Files inspected:

- `/Users/mini-m4-main/Developer/wolnyrolnik/AGENTS.md`
- `/Users/mini-m4-main/Developer/wolnyrolnik/pyproject.toml`
- `/Users/mini-m4-main/Developer/wolnyrolnik/src/auth.py`
- `/Users/mini-m4-main/Developer/wolnyrolnik/src/main.py`
- `/Users/mini-m4-main/Developer/wolnyrolnik/src/database.py`
- `/Users/mini-m4-main/Developer/wolnyrolnik/sql/schema.sql`
- `/Users/mini-m4-main/Developer/wolnyrolnik/sql/migrations/`
- `/Users/mini-m4-main/Developer/wolnyrolnik/sql/queries/`
- `/Users/mini-m4-main/Developer/wolnyrolnik/src/models.py`
- `/Users/mini-m4-main/Developer/wolnyrolnik/src/templates/base.html`
- `/Users/mini-m4-main/Developer/wolnyrolnik/src/templates/farmer_profile.html`
- `/Users/mini-m4-main/Developer/wolnyrolnik/tests/test_smoke.py`

Findings:

- Current auth is Pocket ID OIDC via Authlib.
- `src/auth.py` exposes `get_current_user(request)` as `request.session.get("user")`.
- `/login` either creates a dev session user when `DEV_AUTH=1` or redirects to
  Pocket ID OAuth.
- `/auth/callback` stores `request.session["user"] = dict(user_info)` and upserts
  the app `users` table by `oidc_sub`.
- `/logout` removes `request.session["user"]`.
- Protected routes use fields on the session user dict such as `sub`, `email`, and
  `name`.
- DB is sync SQLAlchemy with raw SQL. `sql/schema.sql` has `users(id, email, name,
  oidc_sub, created_at, last_login)` and no passkey credential table.
- Existing migrations do not include passkey credentials.
- Templates are strict project-owned Basecoat/HTMX. `base.html` reads `user` or
  `request.session.get("user")`; main content target is `#content`.
- Current tests are smoke-only public route checks; adapter migration needs new auth
  route/session tests.

## Recommended adapter contract

### Endpoint contract

The adapter should standardize on the MSDS contract:

- `GET /login`
- `GET /register`
- `POST /api/auth/register/options`
- `POST /api/auth/register/verify`
- `POST /api/auth/login/options`
- `POST /api/auth/login/verify`
- `POST /logout`

Default: **do not include RNKSTR legacy `/start|finish` aliases in core v1**.
Projects may add temporary aliases locally during migration. This keeps the shared
contract unambiguous.

### Proposed `my_auth.fastapi` shape

Add an optional module, not a hard core dependency:

```python
from my_auth.fastapi import PasskeyAuthRouter, PasskeyRouteHooks

auth = PasskeyAuthRouter(
    service=passkey_service,
    hooks=PasskeyRouteHooks(...),
    paths=PasskeyPaths(),
    cookies=PasskeyCookies(),
)
app.include_router(auth.router)
```

The adapter owns ceremony routing and cookie/challenge flow IDs. The project owns
storage, session shape, templates, and permissions.

### Required hooks

Hooks should be async-capable via a tiny internal `maybe_await` helper so the same
adapter works for sync MSDS/WolnyRolnik hooks and async RNKSTR `aiosqlite` hooks.

Minimum hook set:

- `get_session_user(request) -> AuthUser | None`
- `make_registration_user(request, display_name) -> PasskeyUser`
- `get_auth_user(user_id) -> AuthUser | None`
- `login(response, request, user) -> None`
- `logout(response, request) -> None`
- `registration_allowed(request) -> bool | None` or raises `HTTPException`
- `render_login(request) -> Response`
- `render_register(request, *, bootstrap: bool) -> Response`

Optional hooks:

- `after_register(request, user, credential)`
- `after_login(request, user, credential)`
- `on_auth_error(request, exc) -> Response`

`AuthUser` should be a tiny adapter-facing protocol/dataclass with at least:

- `user_id: str`
- `user_handle: bytes`
- `name: str`
- `display_name: str | None`
- optional raw project user object.

The adapter converts `AuthUser` to `PasskeyUser` for `PasskeyService` but never
dictates how projects store sessions.

### Credential storage

Do not add a universal DB schema in the adapter.

Projects provide a `CredentialStore`, already defined by `my-auth` core:

- MSDS: separate `webauthn_credentials` table.
- RNKSTR: current one-credential-per-user table or a project migration to split
  credentials.
- WolnyRolnik: new project migration/store because no passkey credential table exists.

### Challenge storage

Default: use provided `MemoryChallengeStore` for simple deployments and tests.

Plan the adapter so apps can inject a persistent challenge store later, but do not
invent a universal one in this adapter iteration. Document the tradeoff: process
restart between `/options` and `/verify` requires retry.

### Security defaults

- Server-owned `PasskeyConfig`; no client-supplied origin/RP ID derivation.
- Resident/discoverable credentials via core `PasskeyService`.
- Strip `response.userHandle` before login verification when configured for legacy
  compatibility.
- Challenge flow id in an HttpOnly SameSite cookie.
- Session login/logout delegated to project hooks.
- Protected admin/permission APIs remain project-owned and must require real session
  users.
- Registration policy is explicit via hook: bootstrap only, existing-session add
  passkey, invite, or project-specific choice.

### Optional dependency policy

Keep `import my_auth` FastAPI-free.

Add optional/development dependencies:

```toml
[project.optional-dependencies]
fastapi = ["fastapi>=0.115"]

[dependency-groups]
dev = ["pytest>=8", "fastapi>=0.115", "httpx>=0.27"]
```

Importing `my_auth.fastapi` may require FastAPI. Core passkey users should not pay
for FastAPI unless they use the adapter.

### JS helper alignment

Change or document `static/passkey.js` defaults to match the adapter contract.

Recommended default for adapter era:

- `/api/auth/register/options`
- `/api/auth/register/verify`
- `/api/auth/login/options`
- `/api/auth/login/verify`

This is a behavior change for the helper, so include it in tests/docs.

## Out of scope for the adapter

- Universal user DB schema.
- Universal credential DB migration.
- Universal session backend.
- Admin/permission APIs.
- Project nav/sidebar/profile templates.
- Debug/test login endpoints.
- OAuth coexistence policy beyond hook compatibility.

## Test strategy for implementation plan

Use TDD for the adapter implementation:

1. Add failing FastAPI adapter tests in `my-auth` using `TestClient` and fake hooks:
   - router exposes the standard endpoint contract;
   - login options returns JSON challenge and sets challenge cookie;
   - login verify strips `response.userHandle` before delegating;
   - register options/verify call project hooks and set session through `login` hook;
   - registration policy denial returns 403;
   - logout calls project hook and returns configured redirect/JSON.
2. Implement the smallest `my_auth.fastapi` module to pass those tests.
3. Update README with adapter usage for MSDS/RNKSTR/WolnyRolnik-shaped hooks.
4. Run `uv run pytest` in `my-auth`.
5. Only after adapter exists, plan per-project migration work separately.

## Risks and decisions

### Decision 1 — endpoint aliases

Recommended default: standardize only the MSDS endpoint contract in core adapter.
RNKSTR legacy `/start|finish` aliases should be temporary project routes if needed.

Reason: the user's goal is exactly one shared login flow. Supporting both contracts
inside the shared adapter makes the contract ambiguous from day one.

### Decision 2 — async support

Recommended default: adapter hooks are async-capable (`maybe_await`).

Reason: RNKSTR uses async `aiosqlite`; MSDS and WolnyRolnik are sync. Async-capable
hooks avoid excluding RNKSTR without forcing the core `CredentialStore` protocol to
be redesigned immediately.

### Decision 3 — templates

Recommended default: adapter accepts render callbacks and may provide minimal fallback
HTML later, but v1 should not impose templates.

Reason: MSDS, RNKSTR, and WolnyRolnik have different Basecoat/HTMX shells and nav
rules. RNKSTR login/register templates are missing today, and WolnyRolnik has no
passkey login template.

## Approval gate

Status: awaiting approval.

Pending action after approval: write final executable plan to
`.omo/plans/fastapi-adapter.md`.

Recommended plan direction:

1. Build `my_auth.fastapi` as an optional FastAPI adapter module.
2. Standardize the MSDS endpoint contract.
3. Use async-capable project hooks for sessions/templates/user creation.
4. Keep credential persistence project-owned through `CredentialStore`.
5. Update JS helper defaults/docs to the shared `/api/auth/...` endpoints.
6. Do not migrate RNKSTR or WolnyRolnik in the same implementation plan; use the
   adapter implementation as phase 1, then plan migrations separately.

Approval needed: confirm this direction so the final plan file can be written.
