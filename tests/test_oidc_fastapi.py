from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import KeySet

from my_auth.oidc import (
    MemoryAuthorizationCodeStore,
    MemoryTokenStore,
    OIDCClient,
    OIDCProvider,
    OIDCProviderConfig,
    OIDCUserAdapter,
    create_s256_code_challenge,
)
from my_auth.oidc_fastapi import (
    MemorySigningKeyStore,
    OIDCConsentContext,
    OIDCProviderHooks,
    build_oidc_fastapi_plugin,
)


@dataclass(frozen=True)
class _User:
    user_id: str = "user-1"
    name: str = "Alice Example"
    display_name: str = "Alice Example"
    email: str = "alice@example.test"
    is_active: bool = True
    authenticated_at: datetime = datetime(2026, 1, 1, tzinfo=UTC)


def _provider(*, user: _User | None = None, authentication_time=None):
    current_user = user or _User()
    config = OIDCProviderConfig(
        issuer="https://auth.example.test",
        authorization_endpoint="https://auth.example.test/oauth/authorize",
        token_endpoint="https://auth.example.test/oauth/token",
        jwks_uri="https://auth.example.test/oauth/jwks",
        userinfo_endpoint="https://auth.example.test/oauth/userinfo",
    )
    client = OIDCClient(
        client_id="demo-client",
        redirect_uris=("https://client.example.test/callback",),
        scopes=("openid", "profile", "email"),
    )
    users = OIDCUserAdapter(
        claims=lambda _item, _scope: {
            "sub": current_user.user_id,
            "name": current_user.name,
            "email": current_user.email,
            "email_verified": True,
        },
        authentication_time=authentication_time
        or (lambda _item: int(current_user.authenticated_at.timestamp())),
        amr=lambda _item: ("webauthn",),
    )
    provider = OIDCProvider(
        config,
        clients=(client,),
        codes=MemoryAuthorizationCodeStore(),
        tokens=MemoryTokenStore(),
        signing_keys=MemorySigningKeyStore.generate(),
        users=users,
    )

    async def session(_request: Request):
        return current_user

    async def consent(_request: Request, _context: OIDCConsentContext):
        return True

    hooks = OIDCProviderHooks(get_session_user=session, decide_consent=consent)
    app = FastAPI()
    app.include_router(build_oidc_fastapi_plugin(provider=provider, hooks=hooks))
    return TestClient(app, base_url="https://auth.example.test"), provider


def _authorize(client: TestClient, *, verifier: str = "v" * 43, **extra: str):
    params = {
        "response_type": "code",
        "client_id": "demo-client",
        "redirect_uri": "https://client.example.test/callback",
        "scope": "openid profile email",
        "state": "state-123",
        "nonce": "nonce-123",
        "code_challenge": create_s256_code_challenge(verifier),
        "code_challenge_method": "S256",
        **extra,
    }
    return client.get("/oauth/authorize", params=params, follow_redirects=False)


def test_discovery_and_jwks_advertise_only_implemented_profile() -> None:
    client, _provider_value = _provider()

    discovery = client.get("/.well-known/openid-configuration")
    jwks = client.get("/oauth/jwks")

    assert discovery.status_code == 200
    assert discovery.json()["issuer"] == "https://auth.example.test"
    assert discovery.json()["response_types_supported"] == ["code"]
    assert discovery.json()["code_challenge_methods_supported"] == ["S256"]
    assert "refresh_token" not in discovery.json()["grant_types_supported"]
    assert jwks.status_code == 200
    assert len(jwks.json()["keys"]) == 1
    assert jwks.json()["keys"][0]["alg"] == "RS256"
    assert "d" not in jwks.json()["keys"][0]


def test_authorization_code_pkce_token_id_token_and_userinfo_flow() -> None:
    client, provider = _provider()
    verifier = "v" * 43

    authorization = _authorize(client, verifier=verifier)

    assert authorization.status_code == 302
    location = authorization.headers["location"]
    returned = parse_qs(urlsplit(location).query)
    assert returned["state"] == ["state-123"]
    code = returned["code"][0]

    token = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "demo-client",
            "code": code,
            "redirect_uri": "https://client.example.test/callback",
            "code_verifier": verifier,
        },
    )

    assert token.status_code == 200
    token_data = token.json()
    assert token_data["token_type"] == "Bearer"
    assert "refresh_token" not in token_data
    assert token_data["scope"] == "openid profile email"

    public_keys = KeySet.import_key_set(client.get("/oauth/jwks").json())
    decoded = jwt.decode(token_data["id_token"], public_keys, algorithms=["RS256"])
    assert decoded.claims["iss"] == "https://auth.example.test"
    assert decoded.claims["aud"] == "demo-client"
    assert decoded.claims["sub"] == "user-1"
    assert decoded.claims["nonce"] == "nonce-123"
    assert decoded.claims["amr"] == ["webauthn"]
    assert decoded.claims["email"] == "alice@example.test"

    userinfo = client.get(
        "/oauth/userinfo",
        headers={"Authorization": f"Bearer {token_data['access_token']}"},
    )
    assert userinfo.status_code == 200
    assert userinfo.json() == {
        "sub": "user-1",
        "name": "Alice Example",
        "email": "alice@example.test",
        "email_verified": True,
    }

    id_token_as_access_token = client.get(
        "/oauth/userinfo",
        headers={"Authorization": f"Bearer {token_data['id_token']}"},
    )
    assert id_token_as_access_token.status_code == 401
    assert id_token_as_access_token.json()["error"] == "invalid_token"

    replay = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "demo-client",
            "code": code,
            "redirect_uri": "https://client.example.test/callback",
            "code_verifier": verifier,
        },
    )
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"
    assert provider.tokens.get_access_token(token_data["access_token"]) is not None


def test_invalid_redirect_and_pkce_errors_never_redirect_to_untrusted_target() -> None:
    client, _provider_value = _provider()

    invalid_redirect = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "demo-client",
            "redirect_uri": "https://attacker.example.test/callback",
            "scope": "openid",
            "state": "do-not-leak",
            "nonce": "nonce",
            "code_challenge": create_s256_code_challenge("v" * 43),
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert invalid_redirect.status_code == 400
    assert "location" not in invalid_redirect.headers

    missing_pkce = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "demo-client",
            "redirect_uri": "https://client.example.test/callback",
            "scope": "openid",
            "state": "state",
            "nonce": "nonce",
        },
        follow_redirects=False,
    )
    assert missing_pkce.status_code == 302
    assert "error=invalid_request" in missing_pkce.headers["location"]
    assert "attacker" not in missing_pkce.headers["location"]


def test_prompt_none_and_max_age_use_validated_client_error_redirect() -> None:
    old = _User(authenticated_at=datetime.now(UTC) - timedelta(hours=1))
    client, _provider_value = _provider(
        user=old,
        authentication_time=lambda _item: int(
            (datetime.now(UTC) - timedelta(hours=1)).timestamp()
        ),
    )

    response = _authorize(client, prompt="none", max_age="10")

    assert response.status_code == 302
    returned = parse_qs(urlsplit(response.headers["location"]).query)
    assert returned["error"] == ["login_required"]
    assert returned["state"] == ["state-123"]


def test_disabled_session_cannot_authorize() -> None:
    client, _provider_value = _provider(user=_User(is_active=False))

    response = _authorize(client)

    assert response.status_code == 401
    assert response.json()["error"] == "login_required"
