from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from starlette.responses import PlainTextResponse

from my_auth import (
    MemoryChallengeStore,
    MemoryCredentialStore,
    PasskeyConfig,
    PasskeyService,
    PasskeyUser,
    RegistrationContext,
    VerifiedRegistration,
)
from my_auth.fastapi import (
    PasskeyAuthRouter,
    PasskeyCookies,
    PasskeyRouteHooks,
    RenderRegister,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_package_reports_neutral_05x_line() -> None:
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    version = project["project"]["version"]
    package = next(item for item in lock["package"] if item["name"] == "my-auth")

    app_factory_tag = project["tool"]["uv"]["sources"]["app-factory"]["tag"]

    assert version.startswith("0.5.")
    assert package["version"] == version
    assert f"@v{version}" in readme
    assert f"git+https://github.com/mikolaj92/my-auth.git@v{version}" in readme
    assert (
        'uv add "my-auth @ git+https://github.com/mikolaj92/my-auth.git"\n'
        not in readme
    )
    assert "my-auth>=0.5,<0.6" in readme
    assert "invalid historical" not in readme
    assert f"app-factory tag `{app_factory_tag}`" in readme
    assert f"blob/{app_factory_tag}/COMPAT.md" in readme


def test_router_contract_has_no_registration_policy_or_bootstrap_renderer_flag() -> (
    None
):
    import inspect
    from dataclasses import fields

    assert "registration_allowed" not in {
        field.name for field in fields(PasskeyRouteHooks)
    }
    parameters = inspect.signature(RenderRegister.__call__).parameters
    assert "bootstrap" not in parameters


def _app(*, completed: bool = True) -> tuple[TestClient, PasskeyService]:
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

    async def prepare(_request: Request, username: str):
        del username
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

    async def render_login(_request: Request):
        return PlainTextResponse("login")

    async def render_register(request: Request):
        del request
        return PlainTextResponse("register")

    hooks = PasskeyRouteHooks(
        get_session_user=session,
        prepare_registration=prepare,
        complete_registration=complete,
        get_auth_user=auth,
        login=login,
        logout=logout,
        render_login=render_login,
        render_register=render_register,
    )
    app = FastAPI()
    app.include_router(PasskeyAuthRouter(service=service, hooks=hooks).router)
    return TestClient(app), service


def test_options_use_distinct_flow_cookies() -> None:
    client, _ = _app()
    login = client.post("/api/auth/login/options")
    register = client.post("/api/auth/register/options", json={"username": "name"})
    assert "passkey_authentication_challenge=" in login.headers["set-cookie"]
    assert "passkey_registration_challenge=" in register.headers["set-cookie"]


def test_anonymous_registration_is_typed_as_fresh_subject_registration() -> None:
    client, service = _app()

    response = client.post(
        "/api/auth/register/options", json={"username": "new-account"}
    )

    assert response.status_code == 200
    assert isinstance(service.challenges, MemoryChallengeStore)
    flow_id = response.cookies["passkey_registration_challenge"]
    context = service.challenges._records[
        (flow_id, "registration")
    ].registration_context
    assert context is not None
    assert context.kind == "self_registration"
    assert context.user.user_id == "u"


def test_registration_requires_username_field() -> None:
    client, _ = _app()
    assert (
        client.post(
            "/api/auth/register/options", json={"display_name": "legacy"}
        ).status_code
        == 400
    )
    assert (
        client.post("/api/auth/register/options", json={"name": "legacy"}).status_code
        == 400
    )
    assert client.post("/api/auth/register/options", json={}).status_code == 400
    assert (
        client.post(
            "/api/auth/register/options", json={"username": "has space"}
        ).status_code
        == 400
    )


def test_capability_flow_is_bound_by_host_resolver() -> None:
    service = PasskeyService(
        config=PasskeyConfig(
            rp_id="localhost", rp_name="Demo", origin="http://localhost"
        ),
        challenges=MemoryChallengeStore(),
        credentials=MemoryCredentialStore(),
    )
    target = PasskeyUser("target", b"target-handle", "target")
    calls: list[tuple[str, str, str]] = []

    async def none(_request: Request):
        return None

    async def legacy_prepare(_request: Request, _username: str):
        raise AssertionError("capability flow must not use legacy preparation")

    async def resolve(
        _request: Request,
        flow_id: str,
        kind: Literal["invitation", "recovery"],
        capability: str,
    ):
        calls.append((flow_id, kind, capability))
        return RegistrationContext(
            kind=kind,
            user=target,
            capability_id="capability-id",
        )

    async def complete(_request: Request, result: VerifiedRegistration):
        return result.user

    async def auth(_user_id: str):
        return target

    async def noop(*_args):
        return None

    async def page(_request: Request):
        return PlainTextResponse("page")

    async def register_page(request: Request):
        del request
        return PlainTextResponse("register")

    hooks = PasskeyRouteHooks(
        get_session_user=none,
        prepare_registration=legacy_prepare,
        complete_registration=complete,
        get_auth_user=auth,
        login=noop,
        logout=noop,
        render_login=page,
        render_register=register_page,
        prepare_capability_registration_context=resolve,
    )
    app = FastAPI()
    app.include_router(PasskeyAuthRouter(service=service, hooks=hooks).router)
    response = TestClient(app).post(
        "/api/auth/register/options",
        json={"registration_kind": "invitation", "capability": "opaque-token"},
    )
    assert response.status_code == 200
    assert len(calls) == 1
    assert calls[0][1:] == ("invitation", "opaque-token")


def test_capability_flow_hides_invalid_expired_consumed_and_revoked_outcomes() -> None:
    client, _ = _app()
    for body in (
        {"registration_kind": "invitation"},
        {"registration_kind": "recovery", "capability": "unknown"},
    ):
        response = client.post("/api/auth/register/options", json=body)
        assert response.status_code == 400
        assert response.json() == {"detail": "enrollment capability is unavailable"}


def test_settings_cookie_defaults_are_v2() -> None:
    assert (
        PasskeyCookies().authentication_challenge
        != PasskeyCookies().registration_challenge
    )


def test_login_verify_forwards_user_handle_without_legacy_stripping() -> None:
    """Modern WebAuthn path keeps response.userHandle for service validation."""
    from collections.abc import Mapping
    from typing import Any

    from my_auth import AuthenticationResult, PasskeyCredential

    captured: dict[str, Any] = {}
    user = PasskeyUser("u", b"handle", "name")
    stored = PasskeyCredential(b"cred", "u", b"key")

    class RecordingService:
        config = PasskeyConfig(
            rp_id="localhost", rp_name="Demo", origin="http://localhost"
        )

        def begin_authentication(self, **_kwargs):
            raise AssertionError("unused")

        def finish_authentication(
            self,
            *,
            flow_id: str,
            credential: Mapping[str, object] | str,
            require_user_handle: bool = True,
        ) -> AuthenticationResult:
            captured["flow_id"] = flow_id
            captured["credential"] = credential
            captured["require_user_handle"] = require_user_handle
            return AuthenticationResult(user, stored)

        def begin_registration(self, **_kwargs):
            raise AssertionError("unused")

        def verify_registration(self, **_kwargs):
            raise AssertionError("unused")

        def list_credentials(self, **_kwargs):
            return []

        def label_credential(self, **_kwargs):
            raise AssertionError("unused")

        def remove_credential(self, **_kwargs):
            raise AssertionError("unused")

    async def session(_request: Request):
        return None

    async def prepare(_request: Request, username: str):
        del username
        return user

    async def complete(_request: Request, result: VerifiedRegistration):
        del result
        return user

    async def auth(_user_id: str):
        return user

    async def login(_response: Response, _request: Request, _user: PasskeyUser):
        return None

    async def logout(_response: Response, _request: Request):
        return None

    async def render_login(_request: Request):
        return PlainTextResponse("login")

    async def render_register(request: Request):
        del request
        return PlainTextResponse("register")

    hooks = PasskeyRouteHooks(
        get_session_user=session,
        prepare_registration=prepare,
        complete_registration=complete,
        get_auth_user=auth,
        login=login,
        logout=logout,
        render_login=render_login,
        render_register=render_register,
    )
    app = FastAPI()
    app.include_router(
        PasskeyAuthRouter(service=RecordingService(), hooks=hooks).router  # type: ignore[arg-type]
    )
    client = TestClient(app)
    payload = {
        "id": "cred",
        "rawId": "cred",
        "type": "public-key",
        "response": {
            "clientDataJSON": "data",
            "authenticatorData": "auth",
            "signature": "sig",
            "userHandle": "aGFuZGxl",
        },
    }

    response = client.post(
        "/api/auth/login/verify",
        json=payload,
        cookies={"passkey_authentication_challenge": "flow-1"},
    )

    assert response.status_code == 200
    assert captured["flow_id"] == "flow-1"
    assert captured["require_user_handle"] is False
    assert isinstance(captured["credential"], dict)
    response_body = captured["credential"]["response"]
    assert isinstance(response_body, dict)
    assert response_body.get("userHandle") == "aGFuZGxl"
