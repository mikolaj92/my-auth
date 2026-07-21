# my-auth

Minimalny rdzeń passkey-only auth do współdzielenia między projektami typu FastAPI/Starlette/Jinja bez przepisywania WebAuthn od zera.

Rdzeń celowo **nie** zawiera middleware, panelu admina ani systemu sesji. Każdy projekt ma już swoje sesje, bazę i layout. Ten pakiet daje:

- konfigurację RP (`rp_id`, `rp_name`, `origin`) trzymaną po stronie serwera,
- generowanie opcji register/login przez `webauthn`,
- weryfikację register/login przez `webauthn`,
- jednorazowe challenge z TTL,
- modele `PasskeyUser` / `PasskeyCredential` i protokół storage,
- opcjonalny router FastAPI sklejający typowe endpointy z hookami aplikacji,
- opcjonalny adapter `my_auth.fastapi_htmx` dla serwerowo renderowanych
  stron FastAPI/Jinja/HTMX/Basecoat,
- mały vanilla JS helper do `navigator.credentials.create/get`.

`my-auth` jest publicznym projektem open-source na licencji MIT:
<https://github.com/mikolaj92/my-auth>.

## Instalacja z GitHuba

```bash
uv add "my-auth @ git+https://github.com/mikolaj92/my-auth.git"
```

Z adapterem FastAPI:

```bash
uv add "my-auth[fastapi] @ git+https://github.com/mikolaj92/my-auth.git"
```

Z opcjonalnym adapterem FastAPI/Jinja/HTMX UI:

```bash
uv add "my-auth[fastapi-htmx] @ git+https://github.com/mikolaj92/my-auth.git"
```

Albo lokalnie podczas pracy:

```bash
uv add --editable /Users/mini-m4-1/Developer/my-auth
uv sync --dev
uv run pytest
```

Wszystkie komendy w dokumentacji używają `uv` (`uv add`, `uv sync`,
`uv run`).

## Minimalny backend

```python
from my_auth import (
    MemoryChallengeStore,
    PasskeyConfig,
    PasskeyService,
    PasskeyUser,
)

config = PasskeyConfig(
    rp_id="example.com",              # bez scheme/portu
    rp_name="Moja aplikacja",
    origin="https://example.com",     # pełny origin
)

passkeys = PasskeyService(
    config=config,
    challenges=MemoryChallengeStore(),
    credentials=my_storage_adapter,    # implementuje CredentialStore
)
```

## FastAPI adapter

Adapter daje gotowy kształt tras i ciasteczko flow id dla challenge. Sesja aplikacji, polityka rejestracji i renderowanie stron dalej są po stronie projektu przez hooki.

Domyślne trasy:

- `GET /login`
- `GET /register`
- `POST /logout`
- `POST /api/auth/login/options`
- `POST /api/auth/login/verify`
- `POST /api/auth/register/options`
- `POST /api/auth/register/verify`

Najkrótsza ścieżka dla nowej aplikacji to factory składający config,
`PasskeyService` i router:

```python
from my_auth import SQLiteChallengeStore, SQLiteCredentialStore
from my_auth.fastapi import (
    PasskeyFastAPIHooks,
    PasskeyFastAPISettings,
    build_passkey_fastapi_plugin,
)

settings = PasskeyFastAPISettings.from_env()
app.include_router(
    build_passkey_fastapi_plugin(
        settings=settings,
        credentials=SQLiteCredentialStore("app.sqlite3"),
        challenges=SQLiteChallengeStore("app.sqlite3"),
        hooks=PasskeyFastAPIHooks(
            get_session_user=get_session_user,
            make_registration_user=make_registration_user,
            get_auth_user=get_auth_user,
            login=login,
            logout=logout,
            registration_allowed=registration_allowed,
            render_login=render_login,
            render_register=render_register,
        ),
    )
)
```

`PasskeyFastAPISettings.from_env()` czyta `PASSKEY_RP_ID`,
`PASSKEY_RP_NAME`, `PASSKEY_ORIGIN` oraz opcjonalnie m.in.
`PASSKEY_CHALLENGE_TTL_SECONDS`, `PASSKEY_COOKIE_SECURE`,
`PASSKEY_LOGIN_PAGE` i `PASSKEY_CHALLENGE_COOKIE`. Dla aplikacji z własnym
prefixem użyj np. `PasskeyFastAPISettings.from_env(prefix="CONTROL_PLANE_")`.

Bootstrap rejestracji i dodawanie kolejnej passkey pozostają w hookach:
`registration_allowed` decyduje, czy flow jest dozwolony, a
`get_session_user` sprawia, że zalogowany użytkownik rejestruje dodatkową
passkey zamiast tworzyć nowe konto.

```python
from fastapi import FastAPI, Request, Response
from starlette.responses import HTMLResponse

from my_auth import PasskeyCredential, PasskeyUser
from my_auth.fastapi import AuthUser, PasskeyAuthRouter, PasskeyRouteHooks


async def get_session_user(request: Request) -> AuthUser | None:
    user_id = request.session.get("user_id")
    return await users.get_passkey_user(user_id) if user_id else None


async def make_registration_user(request: Request, display_name: str) -> AuthUser:
    # Twórz tylko dla bootstrap/invite flow zaakceptowanego przez registration_allowed.
    return PasskeyUser(
        user_id=await users.next_user_id(),
        user_handle=await users.random_user_handle(),
        name=display_name,
        display_name=display_name,
    )


async def get_auth_user(user_id: str) -> AuthUser | None:
    return await users.get_passkey_user(user_id)


async def login(response: Response, request: Request, user: AuthUser) -> None:
    request.session.clear()  # prevent session fixation
    request.session["user_id"] = user.user_id


async def logout(response: Response, request: Request) -> None:
    request.session.clear()


async def registration_allowed(request: Request) -> bool:
    return bool(request.session.get("invite_ok") or request.session.get("user_id"))


def render_login(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "login.html")


def render_register(request: Request, *, bootstrap: bool) -> HTMLResponse:
    return templates.TemplateResponse(request, "register.html", {"bootstrap": bootstrap})


async def after_register(
    request: Request,
    user: AuthUser,
    credential: PasskeyCredential,
) -> None:
    await audit.log("passkey.register", user.user_id, credential.id_b64url)


app = FastAPI()
app.include_router(
    PasskeyAuthRouter(
        service=passkeys,
        hooks=PasskeyRouteHooks(
            get_session_user=get_session_user,
            make_registration_user=make_registration_user,
            get_auth_user=get_auth_user,
            login=login,
            logout=logout,
            registration_allowed=registration_allowed,
            render_login=render_login,
            render_register=render_register,
            after_register=after_register,
        ),
    ).router
)
```

Challenge flow id siedzi w ciasteczku `passkey_challenge` (`HttpOnly`, `Secure`, `SameSite=Lax`, TTL z `PasskeyConfig.challenge_ttl_seconds`). Adapter usuwa legacy `response.userHandle` przy loginie, bo część przeglądarek nadal potrafi go wysłać mimo discoverable credentials.

Wyjątek od zasady host-owned cookies dotyczy tylko istniejącego flow
WebAuthn: `PasskeyAuthRouter` zarządza ciasteczkami challenge
`passkey_challenge` oraz `passkey_register_name`. Te ciasteczka służą do
jednorazowych opcji/weryfikacji WebAuthn. Adaptery nie przejmują własności
produkcyjnych sesji aplikacji ani app cookies.

## FastAPI/Jinja/HTMX UI adapter

Extra `fastapi-htmx` dodaje opt-in adapter `my_auth.fastapi_htmx` dla
serwerowo renderowanych stron passkey. UI ładuje **ten sam chrome co apki**
przez [app-factory](https://github.com/mikolaj92/app-factory) /
[basecoat-factory](https://github.com/mikolaj92/basecoat-factory) (`btn`, `card`,
theme, HTMX/Alpine). `passkey-ui.css` to tylko layout ceremonii (centrowanie).

Root import pozostaje lekki: `import my_auth` nie importuje FastAPI, Starlette,
Jinja ani zasobów UI. Importuj adapter jawnie tylko w hostach z extra:

```bash
uv add "my-auth[fastapi-htmx]"
# lub lokalnie: uv add --editable ../app-factory
```

```python
from fastapi import FastAPI
from my_auth.fastapi import PasskeyRouteHooks
from my_auth.fastapi_htmx import (
    PasskeyUiConfig,
    PasskeyUiRouter,
    create_passkey_ui_router,
    passkey_ui_static_files,
)

app = FastAPI()
hooks = PasskeyRouteHooks(
    get_session_user=get_session_user,
    make_registration_user=make_registration_user,
    get_auth_user=get_auth_user,
    login=login,
    logout=logout,
    registration_allowed=registration_allowed,
    render_login=render_login_placeholder,
    render_register=render_register_placeholder,
    after_register=after_register,
    after_login=after_login,
)

passkey_ui: PasskeyUiRouter = create_passkey_ui_router(
    service=passkeys,
    hooks=hooks,
    config=PasskeyUiConfig(
        login_success_url="/account",
        register_success_url="/account",
    ),
)
app.include_router(passkey_ui.router)
app.mount(
    passkey_ui.static_mount_path,
    passkey_ui.static_files,
    name="my_auth_fastapi_htmx_static",
)
```

`create_passkey_ui_router` zwraca obiekt z polami `router`,
`static_mount_path` i `static_files`. Host montuje statyczne pliki jawnie
przez zwrócone `static_mount_path` oraz `static_files`. Jeśli potrzebujesz
samego obiektu `StaticFiles`, publiczny helper `passkey_ui_static_files()`
zwraca mount dla pakietowych `passkey-ui.js`, `passkey.js` i
`passkey-ui.css`.

`PasskeyUiConfig` pozwala zmienić `paths`, `cookies`, `static_mount_path`,
`static_url_path`, `passkey_js_url`, CSRF header/token metadata, redirecty po
sukcesie oraz template overrides. `/api/auth/*` nadal pozostaje JSON API z
`PasskeyAuthRouter`; HTMX/Jinja dotyczy stron i fragmentów UI, nie formatu
WebAuthn verify/options.

### Nadpisywanie templatek

Template loader wybierany jest deterministycznie:

1. Jeśli podasz `template_loader`, custom Jinja loader wygrywa.
2. W przeciwnym razie `template_override_directory` tworzy `ChoiceLoader`, w
   którym katalog hosta ma pierwszeństwo, a pakietowe templaty są fallbackiem.
3. Bez obu opcji używane są wyłącznie pakietowe templaty.
4. Podanie jednocześnie `template_loader` i `template_override_directory` jest
   niepoprawne i kończy się `ValueError`.

Przykład katalogu override:

```python
from pathlib import Path
from my_auth.fastapi_htmx import PasskeyUiConfig

config = PasskeyUiConfig(
    template_override_directory=Path("app/templates/my_auth_fastapi_htmx"),
)
```

Przykład pełnego custom loadera:

```python
from jinja2 import DictLoader
from my_auth.fastapi_htmx import PasskeyUiConfig

config = PasskeyUiConfig(
    template_loader=DictLoader({"login.html": "<main>Custom login</main>"}),
)
```

### WebAuthn i bezpieczeństwo hosta

Passkeys wymagają bezpiecznego kontekstu przeglądarki: HTTPS w produkcji albo
lokalny secure context, np. `localhost` podczas developmentu. UI powinien mieć
normalny fallback/komunikat dla przeglądarek bez obsługi WebAuthn.

Host aplikacji nadal jest właścicielem: sessions, app cookies, CSRF
validation, persistence, registration policy, local user provisioning, admin
checks, role/grant changes, audit logging, redirects oraz logout effects.
Security ownership checklist: sessions; app cookies; CSRF validation;
persistence; registration policy; local user provisioning; admin checks;
role/grant changes; audit logging; redirects; logout effects.
Adapter passkey UI nie tworzy produkcyjnej sesji, nie zapisuje użytkowników,
nie nadaje ról, nie zmienia grantów i nie implementuje polityki admina.

Adapter jest bez React, shadcn, Tailwind, npm, bundlera i SPA. To
server-rendered FastAPI/Jinja/HTMX/Basecoat plus małe moduły vanilla JS.

Route-shape dla FastAPI/Starlette:

```python
@router.post("/auth/passkey/register/options")
async def register_options(request):
    # flow_id może być session id, invite token albo bootstrap token
    user = PasskeyUser(
        user_id="app-user-id",
        user_handle=b"stable-random-32-bytes",
        name="mikolaj",
        display_name="Mikołaj",
    )
    return passkeys.begin_registration(flow_id=request.session["flow"], user=user)

@router.post("/auth/passkey/register/verify")
async def register_verify(request):
    credential = passkeys.finish_registration(
        flow_id=request.session["flow"],
        credential=await request.json(),
    )
    return {"credential_id": credential.id_b64url}

@router.post("/auth/passkey/login/options")
async def login_options(request):
    return passkeys.begin_authentication(flow_id=request.session["flow"])

@router.post("/auth/passkey/login/verify")
async def login_verify(request):
    result = passkeys.finish_authentication(
        flow_id=request.session["flow"],
        credential=await request.json(),
    )
    request.session.clear()  # prevent session fixation
    request.session["user_id"] = result.user.user_id
    return {"ok": True}
```

## Storage

Do testów własnych implementacji store importuj współdzielone kontrakty zamiast
kopiować przypadki między aplikacjami:

```python
from my_auth.testing import assert_challenge_store_contract, assert_credential_store_contract


def test_my_passkey_stores() -> None:
    assert_credential_store_contract(lambda: MyCredentialStore(...))
    assert_challenge_store_contract(lambda now: MyChallengeStore(..., now=now))
```

Kontrakty sprawdzają zapis/odczyt użytkownika, lookup po `user_handle`, zapis,
odczyt i listowanie credentiali, aktualizację sign-count po loginie,
jednorazowe `pop()` challenge oraz wygasanie TTL.

Hosty SQLite mogą użyć kanonicznego schematu z pakietu, bez ręcznego kopiowania
DDL:

```python
from my_auth.sqlite_schema import ensure_sqlite_schema, sqlite_schema_sql

ensure_sqlite_schema(connection)  # idempotentnie tworzy tabele, indeksy i FK
ddl_for_migrations = sqlite_schema_sql()
```

Produkcja powinna trzymać użytkowników i credentiale w bazie aplikacji. Ważne: jeden użytkownik może mieć wiele passkey, więc `user_handle` jest unikalny dla użytkownika, **nie** dla credentiala.

Najprostszy wspólny adapter to `SQLiteCredentialStore`:

```python
from my_auth import SQLiteCredentialStore

credentials = SQLiteCredentialStore("app.sqlite3")
passkeys = PasskeyService(
    config=config,
    challenges=MemoryChallengeStore(),
    credentials=credentials,
)
```

Adapter tworzy standardowy schemat idempotentnie, zapisuje `credential_id` i
`user_handle` jako base64url, wspiera wiele credentiali per user, aktualizuje
sign-count po loginie, listuje credentiale usera i pozwala usunąć credential:

```python
credentials.delete_credential(credential_id, user_id=current_user_id)
```

```sql
CREATE TABLE passkey_users (
  user_id TEXT PRIMARY KEY,
  user_handle TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  display_name TEXT
);

CREATE TABLE passkey_credentials (
  credential_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES passkey_users(user_id),
  public_key BLOB NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  device_type TEXT,
  backed_up INTEGER,
  label TEXT,
  created_at TEXT NOT NULL
);
```

Kod powinien mapować `credential_id`, `public_key` i `user_handle` jako bytes w Pythonie, a w JSON/SQL jako base64url string.

Jeśli host używa SQLAlchemy, nie dokładaj drugiej bazy ani zależności do
`my-auth`: odwzoruj powyższe tabele jako modele aplikacji i zaimplementuj
metody protokołu `CredentialStore` (`save_user`, `get_user`,
`get_user_by_handle`, `list_credentials_for_user`, `get_credential`,
`save_credential`, `update_credential_after_login`, `delete_credential`).
Kolumny i konwersje są takie same jak w schemacie SQLite; `transports` to JSON
array albo `NULL`, `backed_up` to nullable boolean/integer, a `created_at` to
ISO datetime.

## Challenge storage

`MemoryChallengeStore` jest dobry do testów, lokalnego developmentu i jednego
procesu. Przy wielu workerach albo wielu instancjach aplikacji użyj wspólnego
store, np. SQLite:

```python
from my_auth import SQLiteChallengeStore

challenges = SQLiteChallengeStore("app.sqlite3")
```

`SQLiteChallengeStore.pop(...)` robi atomowe `DELETE ... RETURNING`, więc
challenge jest jednorazowy również wtedy, gdy drugi worker próbuje użyć tego
samego flow. Wygasłe rekordy są odrzucane i można je sprzątać okresowo:

```python
deleted_count = challenges.cleanup_expired()
```

Standardowy schemat challenge store:

```sql
CREATE TABLE passkey_challenges (
  key TEXT NOT NULL,
  kind TEXT NOT NULL,
  challenge BLOB NOT NULL,
  expires_at TEXT NOT NULL,
  user_id TEXT,
  user_handle TEXT,
  user_name TEXT,
  user_display_name TEXT,
  PRIMARY KEY (key, kind)
);

CREATE INDEX idx_passkey_challenges_expires_at
  ON passkey_challenges(expires_at);
```

## Passkey-only zasady

- Login bez username/password wymaga discoverable credentials / resident keys.
- Rejestracja używa `residentKey: "required"` i domyślnie `userVerification: "required"`.
- Login domyślnie wysyła puste `allowCredentials`, żeby browser mógł pokazać passkeys dla RP.
- Challenge są jednorazowe, rozdzielone na `registration` / `authentication`, z TTL 300 sekund.
- Rejestracja musi być zamknięta: bootstrap token, invite token albo już-zalogowany użytkownik dodający kolejną passkey.
- Recovery bez hasła: wymagaj/dramatycznie zachęcaj do drugiej passkey + admin CLI/invite reset dla istniejącego usera.

## Security checklist w aplikacji

- HTTPS w produkcji. `http://localhost` tylko lokalnie.
- `rp_id` i `origin` z env/config po stronie serwera; nigdy z requestu klienta.
- Secure, HttpOnly, SameSite cookies.
- Po loginie wyczyść/odnów session id, żeby uniknąć session fixation.
- POST verify/logout chroń CSRF-em albo ogranicz endpointy do same-site session flow.
- Nie implementuj WebAuthn crypto samodzielnie; ten pakiet deleguje to do `webauthn`.

## Frontend

Skopiuj albo wystaw `src/my_auth/static/passkey.js` i użyj:

```html
<script type="module">
  import { loginPasskey, registerPasskey } from "/static/passkey.js";

  document.querySelector("#login").addEventListener("click", () => loginPasskey());
  document.querySelector("#register").addEventListener("click", () =>
    registerPasskey({ displayName: document.querySelector("#display-name").value }),
  );
</script>
```

Dla zalogowanego użytkownika dodającego kolejną passkey możesz wywołać `registerPasskey()` bez `displayName`, bo adapter użyje użytkownika z `get_session_user`.
