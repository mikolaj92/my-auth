from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from authlib.oidc.core.grants.util import create_half_hash
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
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
    hash_client_secret,
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


def _provider(
    *,
    user: _User | None = None,
    authentication_time=None,
    client: OIDCClient | None = None,
    consent_result: bool = True,
):
    current_user = user or _User()
    config = OIDCProviderConfig(
        issuer="https://auth.example.test",
        authorization_endpoint="https://auth.example.test/oauth/authorize",
        token_endpoint="https://auth.example.test/oauth/token",
        jwks_uri="https://auth.example.test/oauth/jwks",
        userinfo_endpoint="https://auth.example.test/oauth/userinfo",
    )
    client = client or OIDCClient(
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
        return consent_result

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
    document = discovery.json()
    for key in (
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "userinfo_endpoint",
        "response_types_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
        "claims_supported",
    ):
        assert key in document
    assert document["authorization_endpoint"].startswith(document["issuer"])
    assert document["token_endpoint"].startswith(document["issuer"])
    assert document["jwks_uri"].startswith(document["issuer"])
    assert document["userinfo_endpoint"].startswith(document["issuer"])
    assert "id_token" not in document.get("token_endpoint_auth_methods_supported", [])
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


def test_generic_oidc_relying_party_can_complete_code_flow_from_discovery() -> None:
    """A standard RP uses discovery, not my-auth-specific endpoints."""
    client, _provider_value = _provider()
    verifier = "v" * 43
    discovery = client.get("/.well-known/openid-configuration").json()

    authorization = client.get(
        discovery["authorization_endpoint"].removeprefix("https://auth.example.test"),
        params={
            "response_type": "code",
            "client_id": "demo-client",
            "redirect_uri": "https://client.example.test/callback",
            "scope": "openid profile email",
            "state": "rp-state",
            "nonce": "rp-nonce",
            "code_challenge": create_s256_code_challenge(verifier),
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    code = parse_qs(urlsplit(authorization.headers["location"]).query)["code"][0]
    token = client.post(
        discovery["token_endpoint"].removeprefix("https://auth.example.test"),
        data={
            "grant_type": "authorization_code",
            "client_id": "demo-client",
            "code": code,
            "redirect_uri": "https://client.example.test/callback",
            "code_verifier": verifier,
        },
    ).json()
    keys = KeySet.import_key_set(
        client.get(
            discovery["jwks_uri"].removeprefix("https://auth.example.test")
        ).json()
    )
    claims = jwt.decode(token["id_token"], keys, algorithms=["RS256"]).claims
    userinfo = client.get(
        discovery["userinfo_endpoint"].removeprefix("https://auth.example.test"),
        headers={"Authorization": f"Bearer {token['access_token']}"},
    ).json()

    assert claims["iss"] == discovery["issuer"]
    assert claims["nonce"] == "rp-nonce"
    assert userinfo["sub"] == claims["sub"]
    assert set(userinfo) <= set(discovery["claims_supported"])


def test_unauthenticated_authorize_redirects_to_same_origin_login_not_json_401() -> (
    None
):
    config = OIDCProviderConfig(
        issuer="https://app.example.test",
        authorization_endpoint="https://app.example.test/oauth/authorize",
        token_endpoint="https://app.example.test/oauth/token",
        jwks_uri="https://app.example.test/oauth/jwks",
        userinfo_endpoint="https://app.example.test/oauth/userinfo",
    )
    provider = OIDCProvider(
        config,
        clients=(
            OIDCClient(
                client_id="app",
                redirect_uris=("https://app.example.test/oidc/callback",),
                scopes=("openid", "profile"),
            ),
        ),
        signing_keys=MemorySigningKeyStore.generate(),
    )

    async def no_session(_request: Request):
        return None

    async def consent(_request: Request, _context: OIDCConsentContext):
        return True

    app = FastAPI()
    app.include_router(
        build_oidc_fastapi_plugin(
            provider=provider,
            hooks=OIDCProviderHooks(
                get_session_user=no_session,
                decide_consent=consent,
                login_url="/login",
            ),
        )
    )
    client = TestClient(app, base_url="https://app.example.test")
    verifier = "v" * 43
    response = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "app",
            "redirect_uri": "https://app.example.test/oidc/callback",
            "scope": "openid profile",
            "state": "app-state",
            "nonce": "app-nonce",
            "code_challenge": create_s256_code_challenge(verifier),
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    location = urlsplit(response.headers["location"])
    assert location.path == "/login"
    assert location.hostname in {None, "app.example.test"}
    next_url = parse_qs(location.query)["next"][0]
    assert next_url.startswith("/oauth/authorize")
    assert "client_id=app" in next_url
    assert "attacker" not in next_url
    login_page = client.get("/login", follow_redirects=False)
    assert login_page.status_code == 404


def test_prompt_none_without_session_returns_to_the_client_not_login() -> None:
    config = OIDCProviderConfig(
        issuer="https://app.example.test",
        authorization_endpoint="https://app.example.test/oauth/authorize",
        token_endpoint="https://app.example.test/oauth/token",
        jwks_uri="https://app.example.test/oauth/jwks",
    )
    provider = OIDCProvider(
        config,
        clients=(
            OIDCClient(
                client_id="app",
                redirect_uris=("https://app.example.test/oidc/callback",),
                scopes=("openid",),
            ),
        ),
        signing_keys=MemorySigningKeyStore.generate(),
    )

    async def no_session(_request: Request):
        return None

    async def consent(_request: Request, _context: OIDCConsentContext):
        return True

    app = FastAPI()
    app.include_router(
        build_oidc_fastapi_plugin(
            provider=provider,
            hooks=OIDCProviderHooks(
                get_session_user=no_session,
                decide_consent=consent,
                login_url="/login",
            ),
        )
    )
    client = TestClient(app, base_url="https://app.example.test")
    response = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "app",
            "redirect_uri": "https://app.example.test/oidc/callback",
            "scope": "openid",
            "state": "silent",
            "nonce": "silent-nonce",
            "prompt": "none",
            "code_challenge": create_s256_code_challenge("v" * 43),
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    location = urlsplit(response.headers["location"])
    assert location.path == "/oidc/callback"
    returned = parse_qs(location.query)
    assert returned["error"] == ["login_required"]
    assert returned["state"] == ["silent"]


def test_login_url_must_be_an_application_relative_path() -> None:
    async def no_session(_request: Request):
        return None

    async def consent(_request: Request, _context: OIDCConsentContext):
        return True

    for login_url in (
        "https://attacker.example/login",
        "//attacker.example/login",
        "login",
        "",
    ):
        with pytest.raises(ValueError, match="application-relative"):
            OIDCProviderHooks(
                get_session_user=no_session,
                decide_consent=consent,
                login_url=login_url,
            )


def test_one_app_is_both_openid_provider_and_relying_party() -> None:
    """Same process, same origin: OP routes + RP callback. No second server."""
    user = _User()
    session: dict[str, object] = {}
    config = OIDCProviderConfig(
        issuer="https://app.example.test",
        authorization_endpoint="https://app.example.test/oauth/authorize",
        token_endpoint="https://app.example.test/oauth/token",
        jwks_uri="https://app.example.test/oauth/jwks",
        userinfo_endpoint="https://app.example.test/oauth/userinfo",
    )
    provider = OIDCProvider(
        config,
        clients=(
            OIDCClient(
                client_id="app",
                redirect_uris=("https://app.example.test/oidc/callback",),
                scopes=("openid", "profile", "email"),
            ),
        ),
        signing_keys=MemorySigningKeyStore.generate(),
        users=OIDCUserAdapter(
            claims=lambda _item, _scope: {
                "sub": user.user_id,
                "name": user.name,
                "email": user.email,
            },
            authentication_time=lambda _item: int(user.authenticated_at.timestamp()),
        ),
    )

    async def op_session(_request: Request):
        return session.get("passkey_user")

    async def consent(_request: Request, _context: OIDCConsentContext):
        return True

    app = FastAPI()
    app.include_router(
        build_oidc_fastapi_plugin(
            provider=provider,
            hooks=OIDCProviderHooks(
                get_session_user=op_session,
                decide_consent=consent,
                login_url="/login",
            ),
        )
    )

    @app.get("/login")
    def login(next: str = "/"):
        session["passkey_user"] = user
        return RedirectResponse(next, status_code=302)

    @app.get("/oidc/callback")
    def callback(code: str, state: str):
        session["app_user_id"] = user.user_id
        session["code"] = code
        session["state"] = state
        return RedirectResponse("/", status_code=302)

    @app.get("/")
    def home_page():
        return {"user_id": session.get("app_user_id")}

    client = TestClient(app, base_url="https://app.example.test")
    verifier = "v" * 43
    authorize = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "app",
            "redirect_uri": "https://app.example.test/oidc/callback",
            "scope": "openid profile email",
            "state": "app-state",
            "nonce": "app-nonce",
            "code_challenge": create_s256_code_challenge(verifier),
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert authorize.status_code == 302
    login_location = urlsplit(authorize.headers["location"])
    assert login_location.path == "/login"
    next_url = parse_qs(login_location.query)["next"][0]

    after_login = client.get(
        "/login", params={"next": next_url}, follow_redirects=False
    )
    assert after_login.status_code == 302
    resumed = urlsplit(after_login.headers["location"])
    assert resumed.path == "/oauth/authorize"

    issued = client.get(after_login.headers["location"], follow_redirects=False)
    assert issued.status_code == 302
    callback_url = urlsplit(issued.headers["location"])
    assert callback_url.path == "/oidc/callback"
    returned = parse_qs(callback_url.query)
    assert returned["state"] == ["app-state"]
    code = returned["code"][0]

    token = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "app",
            "code": code,
            "redirect_uri": "https://app.example.test/oidc/callback",
            "code_verifier": verifier,
        },
    )
    assert token.status_code == 200
    assert "id_token" in token.json()
    assert "refresh_token" not in token.json()

    finished = client.get(issued.headers["location"], follow_redirects=False)
    assert finished.status_code == 302
    home = client.get("/")
    assert home.json() == {"user_id": "user-1"}
    assert session["state"] == "app-state"


def _issued_tokens(
    client: TestClient, *, verifier: str = "v" * 43
) -> dict[str, object]:
    authorization = _authorize(client, verifier=verifier)
    code = parse_qs(urlsplit(authorization.headers["location"]).query)["code"][0]
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
    return token.json()


def test_id_token_includes_iat_auth_time_and_at_hash() -> None:
    client, _provider_value = _provider()
    token_data = _issued_tokens(client)
    public_keys = KeySet.import_key_set(client.get("/oauth/jwks").json())
    decoded = jwt.decode(token_data["id_token"], public_keys, algorithms=["RS256"])
    now = int(datetime.now(UTC).timestamp())

    assert decoded.claims["iat"] <= now <= decoded.claims["exp"]
    assert decoded.claims["auth_time"] == int(_User.authenticated_at.timestamp())
    assert decoded.claims["at_hash"] == create_half_hash(
        token_data["access_token"], "RS256"
    ).decode("ascii")


def test_token_response_is_not_stored_by_intermediaries() -> None:
    client, _provider_value = _provider()
    authorization = _authorize(client)
    code = parse_qs(urlsplit(authorization.headers["location"]).query)["code"][0]
    token = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "demo-client",
            "code": code,
            "redirect_uri": "https://client.example.test/callback",
            "code_verifier": "v" * 43,
        },
    )

    assert token.status_code == 200
    assert token.headers["cache-control"] == "no-store"


def test_confidential_client_redeems_code_with_client_secret_basic() -> None:
    secret = "test-confidential-secret"
    registered = OIDCClient(
        client_id="confidential-client",
        redirect_uris=("https://client.example.test/callback",),
        scopes=("openid", "profile"),
        client_secret_hash=hash_client_secret(secret),
    )
    client, _provider_value = _provider(client=registered)
    verifier = "v" * 43
    authorization = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": registered.client_id,
            "redirect_uri": registered.redirect_uris[0],
            "scope": "openid profile",
            "state": "state-confidential",
            "nonce": "nonce-confidential",
            "code_challenge": create_s256_code_challenge(verifier),
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert authorization.status_code == 302
    code = parse_qs(urlsplit(authorization.headers["location"]).query)["code"][0]
    basic = base64.b64encode(f"{registered.client_id}:{secret}".encode()).decode()

    token = client.post(
        "/oauth/token",
        headers={"Authorization": f"Basic {basic}"},
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": registered.redirect_uris[0],
            "code_verifier": verifier,
        },
    )

    assert token.status_code == 200
    assert token.json()["token_type"] == "Bearer"
    public_keys = KeySet.import_key_set(client.get("/oauth/jwks").json())
    decoded = jwt.decode(token.json()["id_token"], public_keys, algorithms=["RS256"])
    assert decoded.claims["aud"] == registered.client_id


def test_consent_denial_returns_access_denied_to_validated_client() -> None:
    client, _provider_value = _provider(consent_result=False)

    response = _authorize(client)

    assert response.status_code == 302
    returned = parse_qs(urlsplit(response.headers["location"]).query)
    assert returned["error"] == ["access_denied"]
    assert returned["state"] == ["state-123"]
    assert "code" not in returned


def test_userinfo_accepts_bearer_token_in_post_body() -> None:
    client, _provider_value = _provider()
    token_data = _issued_tokens(client)

    userinfo = client.post(
        "/oauth/userinfo",
        data={"access_token": token_data["access_token"]},
    )

    assert userinfo.status_code == 200
    assert userinfo.json()["sub"] == "user-1"
    assert userinfo.json()["email"] == "alice@example.test"


def test_userinfo_401_advertises_bearer_error_per_rfc6750() -> None:
    client, _provider_value = _provider()

    missing = client.get("/oauth/userinfo")
    assert missing.status_code == 401
    assert 'error="invalid_token"' in missing.headers["www-authenticate"]

    malformed = client.get(
        "/oauth/userinfo",
        headers={"Authorization": "Bearer not-a-token"},
    )
    assert malformed.status_code == 401
    assert 'error="invalid_token"' in malformed.headers["www-authenticate"]
