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
from my_auth.fastapi import PasskeyRouteHooks
from my_auth.fastapi_htmx import PasskeyUiConfig, create_passkey_ui_router


def test_htmx_router_wraps_v2_hooks() -> None:
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

    async def prepare(_request: Request, _display_name: str):
        return user

    async def complete(_request: Request, result: VerifiedRegistration):
        return result.user

    async def auth(_user_id: str):
        return user

    async def login(_response: Response, _request: Request, _user: PasskeyUser):
        return None

    async def logout(_response: Response, _request: Request):
        return None

    async def policy(_request: Request):
        return True

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
    ui = create_passkey_ui_router(
        service=service, hooks=hooks, config=PasskeyUiConfig()
    )
    app = FastAPI()
    app.include_router(ui.router)
    client = TestClient(app)
    assert client.get("/login").status_code == 200
    assert ui.static_mount_path
