from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.responses import PlainTextResponse
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse

from my_auth import (
    ChallengeNotFound,
    PasskeyConfig,
    PasskeyCredential,
    PasskeyUser,
    SQLiteChallengeStore,
    SQLiteCredentialStore,
)
from my_auth.fastapi import (
    AuthUser,
    PasskeyAuthRouter,
    PasskeyFastAPISettings,
    PasskeyRouteHooks,
    build_passkey_fastapi_plugin,
)


class FakePasskeyService:
    def __init__(self) -> None:
        self.config = SimpleNamespace(origin="https://example.com", challenge_ttl_seconds=300)
        self.calls: list[tuple[str, Any]] = []
        self.consumed_authentication_flows: set[str] = set()
        self.consumed_registration_flows: set[str] = set()
        self.fail_authentication = False
        self.fail_registration = False

    def begin_authentication(self, *, flow_id: str) -> dict[str, Any]:
        self.calls.append(("begin_authentication", flow_id))
        return {"challenge": "login-challenge", "rpId": "example.com", "allowCredentials": []}

    def finish_authentication(
        self,
        *,
        flow_id: str,
        credential: dict[str, Any],
        require_user_handle: bool = True,
    ) -> SimpleNamespace:
        self.calls.append(
            (
                "finish_authentication",
                {
                    "flow_id": flow_id,
                    "credential": credential,
                    "require_user_handle": require_user_handle,
                },
            )
        )
        if self.fail_authentication or flow_id in self.consumed_authentication_flows:
            raise ChallengeNotFound("missing or expired authentication challenge")
        if credential.get("id") == "invalid-webauthn":
            raise InvalidAuthenticationResponse("invalid authentication response")
        self.consumed_authentication_flows.add(flow_id)
        return SimpleNamespace(
            user=PasskeyUser(user_id="u1", user_handle=b"handle", name="mikolaj"),
            credential=PasskeyCredential(credential_id=b"credential-id", user_id="u1", public_key=b"pk"),
        )

    def begin_registration(self, *, flow_id: str, user: PasskeyUser) -> dict[str, Any]:
        self.calls.append(("begin_registration", {"flow_id": flow_id, "user": user}))
        return {
            "challenge": "register-challenge",
            "rp": {"id": "example.com", "name": "Example"},
            "user": {"id": user.user_handle_b64url, "name": user.name},
        }

    def finish_registration(self, *, flow_id: str, credential: dict[str, Any]) -> PasskeyCredential:
        self.calls.append(("finish_registration", {"flow_id": flow_id, "credential": credential}))
        if self.fail_registration:
            raise InvalidRegistrationResponse("invalid registration response")
        if flow_id in self.consumed_registration_flows:
            raise ChallengeNotFound("missing or expired registration challenge")
        self.consumed_registration_flows.add(flow_id)
        return PasskeyCredential(credential_id=b"new-credential", user_id="new-user", public_key=b"pk")


class HookRecorder:
    def __init__(self) -> None:
        self.order: list[str] = []
        self.allowed = True
        self.session_user: AuthUser | None = None
        self.users = {
            "u1": AuthUser(user_id="u1", user_handle=b"handle", name="mikolaj"),
            "new-user": AuthUser(user_id="new-user", user_handle=b"new-handle", name="Alice"),
        }

    async def get_session_user(self, request) -> AuthUser | None:  # noqa: ANN001
        self.order.append("get_session_user")
        return self.session_user

    async def make_registration_user(self, request, display_name: str) -> AuthUser:  # noqa: ANN001
        self.order.append("make_registration_user")
        user = AuthUser(
            user_id="new-user",
            user_handle=b"new-handle",
            name=display_name,
            display_name=display_name,
        )
        self.users[user.user_id] = user
        return user

    async def get_auth_user(self, user_id: str) -> AuthUser | None:
        self.order.append("get_auth_user")
        return self.users.get(user_id)

    async def login(self, response, request, user: AuthUser) -> None:  # noqa: ANN001
        self.order.append("login")
        response.set_cookie("app_session", user.user_id)

    async def logout(self, response, request) -> None:  # noqa: ANN001
        self.order.append("logout")
        response.delete_cookie("app_session")

    async def registration_allowed(self, request) -> bool:  # noqa: ANN001
        self.order.append("registration_allowed")
        return self.allowed

    def render_login(self, request) -> PlainTextResponse:  # noqa: ANN001
        return PlainTextResponse("login")

    def render_register(self, request, *, bootstrap: bool) -> PlainTextResponse:  # noqa: ANN001
        return PlainTextResponse(f"register:{bootstrap}")

    async def after_register(self, request, user: AuthUser, credential: PasskeyCredential) -> None:  # noqa: ANN001
        self.order.append("after_register")

    async def after_login(self, request, user: AuthUser, credential: PasskeyCredential) -> None:  # noqa: ANN001
        self.order.append("after_login")


def hooks_for(recorder: HookRecorder) -> PasskeyRouteHooks:
    return PasskeyRouteHooks(
        get_session_user=recorder.get_session_user,
        make_registration_user=recorder.make_registration_user,
        get_auth_user=recorder.get_auth_user,
        login=recorder.login,
        logout=recorder.logout,
        registration_allowed=recorder.registration_allowed,
        render_login=recorder.render_login,
        render_register=recorder.render_register,
        after_register=recorder.after_register,
        after_login=recorder.after_login,
    )


def test_fastapi_settings_from_env_supports_paths_cookies_and_custom_prefix() -> None:
    settings = PasskeyFastAPISettings.from_env(
        {
            "PASSKEY_RP_ID": "localhost",
            "PASSKEY_RP_NAME": "Demo",
            "PASSKEY_ORIGIN": "http://localhost:8000",
            "PASSKEY_TIMEOUT_MS": "1234",
            "PASSKEY_CHALLENGE_TTL_SECONDS": "45",
            "PASSKEY_USER_VERIFICATION": "preferred",
            "PASSKEY_LOGIN_PAGE": "/signin",
            "PASSKEY_CHALLENGE_COOKIE": "flow",
            "PASSKEY_COOKIE_SECURE": "false",
            "PASSKEY_COOKIE_SAMESITE": "strict",
        }
    )

    assert settings.passkey_config() == PasskeyConfig(
        rp_id="localhost",
        rp_name="Demo",
        origin="http://localhost:8000",
        timeout_ms=1234,
        challenge_ttl_seconds=45,
        user_verification="preferred",
    )
    assert settings.paths.login_page == "/signin"
    assert settings.cookies.challenge == "flow"
    assert settings.cookies.secure is False
    assert settings.cookies.samesite == "strict"
    assert PasskeyFastAPISettings.from_env(
        {
            "CONTROL_PLANE_RP_ID": "localhost",
            "CONTROL_PLANE_RP_NAME": "Control Plane",
            "CONTROL_PLANE_ORIGIN": "http://localhost:8000",
        },
        prefix="CONTROL_PLANE_",
    ).rp_name == "Control Plane"


def test_fastapi_settings_from_env_rejects_missing_or_invalid_values() -> None:
    with pytest.raises(ValueError, match="PASSKEY_RP_ID"):
        PasskeyFastAPISettings.from_env({})
    with pytest.raises(ValueError, match="PASSKEY_COOKIE_SECURE"):
        PasskeyFastAPISettings.from_env(
            {
                "PASSKEY_RP_ID": "localhost",
                "PASSKEY_RP_NAME": "Demo",
                "PASSKEY_ORIGIN": "http://localhost:8000",
                "PASSKEY_COOKIE_SECURE": "maybe",
            }
        )


def test_build_passkey_fastapi_plugin_wires_service_settings_and_shared_stores(tmp_path) -> None:
    settings = PasskeyFastAPISettings.from_env(
        {
            "PASSKEY_RP_ID": "localhost",
            "PASSKEY_RP_NAME": "Demo",
            "PASSKEY_ORIGIN": "http://localhost:8000",
            "PASSKEY_CHALLENGE_TTL_SECONDS": "45",
            "PASSKEY_LOGIN_PAGE": "/signin",
            "PASSKEY_CHALLENGE_COOKIE": "flow",
            "PASSKEY_COOKIE_SECURE": "false",
        }
    )
    database = tmp_path / "passkeys.sqlite"
    challenges = SQLiteChallengeStore(database)
    credentials = SQLiteCredentialStore(database)
    recorder = HookRecorder()
    app = FastAPI()
    app.include_router(
        build_passkey_fastapi_plugin(
            settings=settings,
            credentials=credentials,
            challenges=challenges,
            hooks=hooks_for(recorder),
        )
    )
    client = TestClient(app)

    login = client.get("/signin")
    options = client.post("/api/auth/login/options")

    assert login.text == "login"
    assert options.status_code == 200
    assert options.json()["rpId"] == "localhost"
    assert options.cookies["flow"]
    assert "Max-Age=45" in options.headers["set-cookie"]
    assert "Secure" not in options.headers["set-cookie"]
    record = challenges.pop(key=options.cookies["flow"], kind="authentication")
    assert record.kind == "authentication"


def app_client(
    *, service: FakePasskeyService | None = None, recorder: HookRecorder | None = None
) -> tuple[TestClient, FakePasskeyService, HookRecorder]:
    service = service or FakePasskeyService()
    recorder = recorder or HookRecorder()
    app = FastAPI()
    app.include_router(PasskeyAuthRouter(service=service, hooks=hooks_for(recorder)).router)
    return TestClient(app), service, recorder


def test_router_exposes_standard_endpoints() -> None:
    client, _, _ = app_client()

    assert client.get("/login").text == "login"
    assert client.get("/register").text == "register:True"
    assert client.post("/api/auth/login/options").status_code == 200
    assert client.post("/api/auth/register/options", json={"display_name": "Alice"}).status_code == 200
    assert client.post("/logout", follow_redirects=False).status_code == 303


def test_login_options_returns_options_and_sets_secure_challenge_cookie() -> None:
    client, _, _ = app_client()

    response = client.post("/api/auth/login/options")

    assert response.json() == {"challenge": "login-challenge", "rpId": "example.com", "allowCredentials": []}
    assert response.cookies["passkey_challenge"]
    set_cookie = response.headers["set-cookie"]
    assert "passkey_challenge=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=lax" in set_cookie
    assert "Secure" in set_cookie
    assert "Max-Age=300" in set_cookie


def test_login_verify_strips_legacy_user_handle_and_runs_async_hooks_in_order() -> None:
    client, service, recorder = app_client()
    flow_id = client.post("/api/auth/login/options").cookies["passkey_challenge"]
    recorder.order.clear()

    response = client.post(
        "/api/auth/login/verify",
        json={"id": "credential", "response": {"clientDataJSON": "abc", "userHandle": "legacy"}},
        cookies={"passkey_challenge": flow_id},
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert response.cookies["app_session"] == "u1"
    assert recorder.order == ["get_auth_user", "login", "after_login"]
    finish_call = service.calls[-1][1]
    assert finish_call["require_user_handle"] is False
    assert "userHandle" not in finish_call["credential"]["response"]


def test_login_verify_replay_fails_after_challenge_is_consumed() -> None:
    client, _, recorder = app_client()
    flow_id = client.post("/api/auth/login/options").cookies["passkey_challenge"]

    assert client.post("/api/auth/login/verify", json={"id": "credential"}, cookies={"passkey_challenge": flow_id}).status_code == 200
    recorder.order.clear()
    replay = client.post("/api/auth/login/verify", json={"id": "credential"}, cookies={"passkey_challenge": flow_id})

    assert replay.status_code == 400
    assert recorder.order == []


def test_challenge_expiry_returns_400_style_auth_error() -> None:
    client, service, recorder = app_client()
    service.fail_authentication = True

    response = client.post("/api/auth/login/verify", json={"id": "credential"}, cookies={"passkey_challenge": "expired"})

    assert response.status_code == 400
    assert "missing or expired" in response.json()["detail"]
    assert recorder.order == []


def test_registration_policy_denial_returns_403_without_creating_challenge() -> None:
    recorder = HookRecorder()
    recorder.allowed = False
    client, service, _ = app_client(recorder=recorder)

    response = client.post("/api/auth/register/options", json={"display_name": "Alice"})

    assert response.status_code == 403
    assert "passkey_challenge" not in response.cookies
    assert not service.calls


def test_register_options_and_verify_call_hooks_in_order() -> None:
    client, service, recorder = app_client()

    options = client.post("/api/auth/register/options", json={"display_name": "Alice"})
    flow_id = options.cookies["passkey_challenge"]

    assert options.status_code == 200
    assert "passkey_register_name" not in options.cookies
    assert recorder.order == ["registration_allowed", "get_session_user", "make_registration_user"]
    begin_call = service.calls[-1][1]
    assert begin_call["user"] == PasskeyUser(
        user_id="new-user",
        user_handle=b"new-handle",
        name="Alice",
        display_name="Alice",
    )

    recorder.order.clear()
    verify = client.post("/api/auth/register/verify", json={"id": "new-credential"}, cookies={"passkey_challenge": flow_id})

    assert verify.status_code == 200
    assert verify.json() == {"ok": True}
    assert recorder.order == ["get_session_user", "get_auth_user", "login", "after_register"]


def test_login_hooks_do_not_run_when_webauthn_verification_fails() -> None:
    client, service, recorder = app_client()
    service.fail_authentication = True

    response = client.post("/api/auth/login/verify", json={"id": "credential"}, cookies={"passkey_challenge": "flow"})

    assert response.status_code == 400
    assert "login" not in recorder.order
    assert "after_login" not in recorder.order


def test_login_verify_maps_webauthn_library_failures_to_400() -> None:
    client, _, recorder = app_client()
    flow_id = client.post("/api/auth/login/options").cookies["passkey_challenge"]
    recorder.order.clear()

    response = client.post(
        "/api/auth/login/verify",
        json={"id": "invalid-webauthn"},
        cookies={"passkey_challenge": flow_id},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "invalid authentication response"
    assert recorder.order == []


def test_register_verify_maps_webauthn_library_failures_to_400() -> None:
    service = FakePasskeyService()
    service.fail_registration = True
    client, _, recorder = app_client(service=service)
    flow_id = client.post("/api/auth/register/options", json={"display_name": "Alice"}).cookies["passkey_challenge"]
    recorder.order.clear()

    response = client.post(
        "/api/auth/register/verify",
        json={"id": "new-credential"},
        cookies={"passkey_challenge": flow_id},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "invalid registration response"
    assert recorder.order == ["get_session_user"]


def test_logout_calls_hook_deletes_adapter_cookies_and_redirects() -> None:
    client, _, recorder = app_client()

    response = client.post("/logout", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert recorder.order == ["logout"]
    set_cookie = response.headers.get_list("set-cookie")
    assert any(cookie.startswith("passkey_challenge=") and "Max-Age=0" in cookie for cookie in set_cookie)
    assert any(cookie.startswith("passkey_register_name=") and "Max-Age=0" in cookie for cookie in set_cookie)


def test_static_js_defaults_match_adapter_endpoints() -> None:
    js = Path("src/my_auth/static/passkey.js").read_text()

    assert 'optionsUrl = "/api/auth/register/options"' in js
    assert 'verifyUrl = "/api/auth/register/verify"' in js
    assert 'optionsUrl = "/api/auth/login/options"' in js
    assert 'verifyUrl = "/api/auth/login/verify"' in js


def test_static_js_can_send_registration_display_name() -> None:
    js = Path("src/my_auth/static/passkey.js").read_text()
    register_js = js.split("export async function registerPasskey", 1)[1].split(
        "export async function loginPasskey", 1
    )[0]

    assert "displayName" in register_js
    assert "display_name" in register_js
    assert "optionsBody = {}" in register_js
    assert "postJSON(optionsUrl, registrationOptionsBody, fetchOptions)" in register_js
    assert "postJSON(optionsUrl, {}, fetchOptions)" not in register_js


def test_core_import_does_not_import_fastapi_adapter() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import my_auth; print('my_auth.fastapi' in sys.modules)",
        ],
        check=True,
        text=True,
        capture_output=True,
    )

    assert result.stdout.strip() == "False"


def test_adapter_exports_only_router_hooks_and_path_cookie_config() -> None:
    import my_auth.fastapi as fastapi_adapter

    assert set(fastapi_adapter.__all__) == {
        "AuthUser",
        "PasskeyFastAPIHooks",
        "PasskeyFastAPISettings",
        "PasskeyAuthRouter",
        "PasskeyCookies",
        "PasskeyPaths",
        "PasskeyRouteHooks",
        "build_passkey_fastapi_plugin",
    }
