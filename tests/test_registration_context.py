from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import cast

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.responses import PlainTextResponse

from my_auth import (
    MemoryChallengeStore,
    MemoryCredentialStore,
    PasskeyConfig,
    PasskeyService,
    PasskeyUser,
    RegistrationContext,
    RegistrationKind,
    SQLiteChallengeStore,
    VerifiedRegistration,
    ensure_sqlite_schema,
    inspect_sqlite_schema,
    migrate_sqlite_schema,
    registration_context_from_capability,
)
from my_auth.fastapi import PasskeyAuthRouter, PasskeyRouteHooks


def test_context_requires_capability_for_invitation_and_recovery() -> None:
    user = PasskeyUser("user", b"handle", "user")
    for kind in ("invitation", "recovery"):
        with pytest.raises(ValueError, match="requires a capability"):
            RegistrationContext(kind=cast(RegistrationKind, kind), user=user)
    with pytest.raises(ValueError, match="cannot use a capability"):
        RegistrationContext(kind="bootstrap", user=user, capability_id="cap")


def test_capability_context_rejects_cross_subject_and_wrong_purpose() -> None:
    user = PasskeyUser("user-a", b"handle-a", "user-a")
    context = registration_context_from_capability(
        kind="invitation",
        user=user,
        capability_id="cap",
        capability_subject="user-a",
        capability_purpose="invitation",
    )
    assert context.user == user
    with pytest.raises(ValueError, match="does not match"):
        registration_context_from_capability(
            kind="invitation",
            user=user,
            capability_id="cap",
            capability_subject="user-b",
            capability_purpose="invitation",
        )
    with pytest.raises(ValueError, match="does not match"):
        registration_context_from_capability(
            kind="recovery",
            user=user,
            capability_id="cap",
            capability_subject="user-a",
            capability_purpose="invitation",
        )


def test_service_binds_context_to_challenge_and_verified_result(monkeypatch) -> None:
    challenges = MemoryChallengeStore()
    service = PasskeyService(
        config=PasskeyConfig(
            rp_id="localhost", rp_name="Demo", origin="http://localhost"
        ),
        challenges=challenges,
        credentials=MemoryCredentialStore(),
    )
    user = PasskeyUser("target", b"target-handle", "target")
    context = RegistrationContext(
        kind="invitation", user=user, capability_id="capability-1"
    )
    service.begin_registration(flow_id="flow", context=context)
    record = challenges._records[("flow", "registration")]
    assert record.registration_context == context

    class Verified:
        credential_id = b"credential"
        credential_public_key = b"public-key"
        sign_count = 0
        credential_device_type = None
        credential_backed_up = None

    monkeypatch.setattr("my_auth.passkeys.verify_registration_response", lambda **_: Verified())
    result = service.verify_registration(
        flow_id="flow", credential={"id": "Y3JlZGVudGlhbA", "response": {}}
    )
    assert result.user == user
    assert result.context == context


def test_sqlite_challenge_persists_registration_context(tmp_path: Path) -> None:
    database = tmp_path / "auth.sqlite3"
    with sqlite3.connect(database) as connection:
        ensure_sqlite_schema(connection)
    store = SQLiteChallengeStore(database)
    user = PasskeyUser("target", b"handle", "target")
    context = RegistrationContext(
        kind="recovery", user=user, capability_id="recovery-cap"
    )
    store.save(
        key="flow",
        kind="registration",
        challenge=b"challenge",
        ttl_seconds=60,
        registration_context=context,
    )
    assert store.pop(key="flow", kind="registration").registration_context == context


def test_v2_schema_migrates_to_context_aware_v3(tmp_path: Path) -> None:
    database = tmp_path / "v2.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            PRAGMA foreign_keys=ON;
            CREATE TABLE my_auth_schema (schema_version INTEGER NOT NULL);
            CREATE TABLE passkey_users (user_id TEXT PRIMARY KEY, user_handle TEXT NOT NULL UNIQUE, name TEXT NOT NULL, display_name TEXT);
            CREATE TABLE passkey_credentials (credential_id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES passkey_users(user_id) ON DELETE CASCADE, public_key BLOB NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0, transports TEXT, device_type TEXT, backed_up INTEGER, label TEXT, created_at TEXT NOT NULL);
            CREATE INDEX idx_passkey_credentials_user_id ON passkey_credentials(user_id);
            CREATE TABLE passkey_challenges (key TEXT NOT NULL, kind TEXT NOT NULL, challenge BLOB NOT NULL, expires_at TEXT NOT NULL, user_id TEXT, user_handle TEXT, user_name TEXT, user_display_name TEXT, PRIMARY KEY (key, kind));
            CREATE INDEX idx_passkey_challenges_expires_at ON passkey_challenges(expires_at);
            INSERT INTO my_auth_schema VALUES (2);
            """
        )
        assert inspect_sqlite_schema(connection).state == "legacy"
        inspection = migrate_sqlite_schema(connection)
        assert inspection.state == "current"
        assert inspection.version == 3
        columns = {
            cast(str, row[1])
            for row in connection.execute("PRAGMA table_info(passkey_challenges)")
        }
        assert {"registration_kind", "capability_id"}.issubset(columns)


def _router_app(
    *, session_user: PasskeyUser | None = None
) -> tuple[TestClient, list[RegistrationContext]]:
    service = PasskeyService(
        config=PasskeyConfig(
            rp_id="localhost", rp_name="Demo", origin="http://localhost"
        ),
        challenges=MemoryChallengeStore(),
        credentials=MemoryCredentialStore(),
    )
    prepared: list[RegistrationContext] = []

    async def session(_request: Request):
        return session_user

    async def legacy_prepare(_request: Request, _username: str):
        raise AssertionError("typed context hook must replace legacy preparation")

    async def prepare_context(_request: Request, flow_id: str, _username: str):
        context = RegistrationContext(
            kind="invitation",
            user=PasskeyUser("target", b"target-handle", "target"),
            capability_id=f"cap-{flow_id}",
        )
        prepared.append(context)
        return context

    async def complete(_request: Request, result: VerifiedRegistration):
        return result.user

    async def auth(_user_id: str):
        return None

    async def noop(*_args):
        return None

    async def allowed(_request: Request):
        return True

    async def render(_request: Request):
        return PlainTextResponse("login")

    async def render_register(request: Request, *, bootstrap: bool):
        del request
        return PlainTextResponse(str(bootstrap))

    hooks = PasskeyRouteHooks(
        get_session_user=session,
        prepare_registration=legacy_prepare,
        complete_registration=complete,
        get_auth_user=auth,
        login=noop,
        logout=noop,
        registration_allowed=allowed,
        render_login=render,
        render_register=render_register,
        prepare_registration_context=prepare_context,
    )
    app = FastAPI()
    app.include_router(PasskeyAuthRouter(service=service, hooks=hooks).router)
    return TestClient(app), prepared


def test_router_resolves_anonymous_context_after_allocating_flow() -> None:
    client, prepared = _router_app()
    response = client.post(
        "/api/auth/register/options", json={"username": "ignored-by-identity-policy"}
    )
    assert response.status_code == 200
    assert len(prepared) == 1
    flow = response.cookies["passkey_registration_challenge"]
    assert prepared[0].capability_id == f"cap-{flow}"
    assert prepared[0].user.user_id == "target"


def test_authenticated_registration_ignores_request_identity() -> None:
    current = PasskeyUser("current", b"current-handle", "current")
    client, prepared = _router_app(session_user=current)
    response = client.post(
        "/api/auth/register/options", json={"username": "attacker-target"}
    )
    assert response.status_code == 200
    assert prepared == []
