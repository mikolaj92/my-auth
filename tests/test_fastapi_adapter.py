from __future__ import annotations

from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from starlette.responses import PlainTextResponse

from my_auth import (
    MemoryChallengeStore,
    MemoryCredentialStore,
    PasskeyConfig,
    PasskeyService,
    PasskeyUser,
    VerifiedRegistration,
)
from my_auth.fastapi import PasskeyAuthRouter, PasskeyCookies, PasskeyRouteHooks


def _app(
    *, allowed: bool = True, completed: bool = True
) -> tuple[TestClient, PasskeyService]:
    service = PasskeyService(
        config=PasskeyConfig(
            rp_id="localhost", rp_name="Demo", origin="http://localhost"
        ),
        challenges=MemoryChallengeStore(),
        credentials=MemoryCredentialStore(),
    )
    user = PasskeyUser("u", b"handle", "name")

    async def session(_request: Request):
        return None

    async def prepare(_request: Request, display_name: str):
        return user

    async def complete(_request: Request, result: VerifiedRegistration):
        if completed:
            service.credentials.save_registration(result)
            return result.user
        return None

    async def auth(_user_id: str):
        return user

    async def login(_response: Response, _request: Request, _user: PasskeyUser):
        return None

    async def logout(_response: Response, _request: Request):
        return None

    async def policy(_request: Request):
        return allowed

    async def render_login(_request: Request):
        return PlainTextResponse("login")

    async def render_register(request: Request, *, bootstrap: bool):
        del request, bootstrap
        return PlainTextResponse("register")

    hooks = PasskeyRouteHooks(
        get_session_user=session,
        prepare_registration=prepare,
        complete_registration=complete,
        get_auth_user=auth,
        login=login,
        logout=logout,
        registration_allowed=policy,
        render_login=render_login,
        render_register=render_register,
    )
    app = FastAPI()
    app.include_router(PasskeyAuthRouter(service=service, hooks=hooks).router)
    return TestClient(app), service


def test_options_use_distinct_flow_cookies() -> None:
    client, _ = _app()
    login = client.post("/api/auth/login/options")
    register = client.post("/api/auth/register/options", json={"display_name": "name"})
    assert "passkey_authentication_challenge=" in login.headers["set-cookie"]
    assert "passkey_registration_challenge=" in register.headers["set-cookie"]


def test_registration_policy_denial_prevents_challenge() -> None:
    client, service = _app(allowed=False)
    assert (
        client.post(
            "/api/auth/register/options", json={"display_name": "name"}
        ).status_code
        == 403
    )
    assert isinstance(service.challenges, MemoryChallengeStore)
    assert service.challenges._records == {}


def test_settings_cookie_defaults_are_v2() -> None:
    assert (
        PasskeyCookies().authentication_challenge
        != PasskeyCookies().registration_challenge
    )
