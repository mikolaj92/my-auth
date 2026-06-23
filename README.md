# my-auth

Minimalny rdzeń passkey-only auth do współdzielenia między projektami typu FastAPI/Starlette/Jinja bez przepisywania WebAuthn od zera.

V0 celowo **nie** zawiera routerów, middleware, panelu admina ani systemu sesji. Każdy projekt ma już swoje sesje, bazę i layout. Ten pakiet daje tylko:

- konfigurację RP (`rp_id`, `rp_name`, `origin`) trzymaną po stronie serwera,
- generowanie opcji register/login przez `webauthn`,
- weryfikację register/login przez `webauthn`,
- jednorazowe challenge z TTL,
- modele `PasskeyUser` / `PasskeyCredential` i protokół storage,
- mały vanilla JS helper do `navigator.credentials.create/get`.

## Instalacja z GitHuba

```bash
uv add "git+https://github.com/mikolaj92/my-auth"
```

Albo lokalnie podczas pracy:

```bash
uv add --editable /Users/mini-m4-main/Developer/my-auth
```

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

Produkcja powinna trzymać użytkowników i credentiale w bazie aplikacji. Ważne: jeden użytkownik może mieć wiele passkey, więc `user_handle` jest unikalny dla użytkownika, **nie** dla credentiala.

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
  document.querySelector("#register").addEventListener("click", () => registerPasskey());
</script>
```
