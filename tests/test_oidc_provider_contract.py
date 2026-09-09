"""Contract-first seam for the my-auth OpenID Provider."""

import pytest

from my_auth.oidc import (
    AuthorizationCode,
    MemoryAuthorizationCodeStore,
    MemoryTokenStore,
    OIDCClient,
    OIDCProviderConfig,
    create_s256_code_challenge,
    validate_client_redirect,
)


def test_provider_metadata_exposes_only_the_first_supported_profile() -> None:
    config = OIDCProviderConfig(
        issuer="https://auth.example.test",
        authorization_endpoint="https://auth.example.test/authorize",
        token_endpoint="https://auth.example.test/token",
        jwks_uri="https://auth.example.test/jwks.json",
    )
    metadata = config.metadata()
    assert metadata["issuer"] == "https://auth.example.test"
    assert metadata["response_types_supported"] == ["code"]
    assert metadata["grant_types_supported"] == ["authorization_code"]
    assert metadata["code_challenge_methods_supported"] == ["S256"]
    assert metadata["id_token_signing_alg_values_supported"] == ["RS256"]
    response_types = metadata["response_types_supported"]
    grant_types = metadata["grant_types_supported"]
    assert isinstance(response_types, list)
    assert isinstance(grant_types, list)
    assert "implicit" not in response_types
    assert "password" not in grant_types
    assert metadata["claims_supported"] == [
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
        "nonce",
        "auth_time",
        "amr",
        "acr",
        "name",
        "email",
        "email_verified",
    ]
    assert metadata["claim_types_supported"] == ["normal"]
    signing_algs = metadata["id_token_signing_alg_values_supported"]
    token_auth = metadata["token_endpoint_auth_methods_supported"]
    assert isinstance(signing_algs, list)
    assert isinstance(token_auth, list)
    assert signing_algs == ["RS256"]
    assert "HS256" not in signing_algs
    assert token_auth == [
        "none",
        "client_secret_basic",
    ]
    assert "client_secret_post" not in token_auth
    assert metadata["request_parameter_supported"] is False
    assert metadata["request_uri_parameter_supported"] is False
    assert "refresh_token" not in grant_types


def test_client_requires_exact_redirect_and_openid_code_profile() -> None:
    client = OIDCClient(
        client_id="app",
        redirect_uris=("https://app.example.test/callback",),
        scopes=("openid", "profile"),
    )
    assert validate_client_redirect(client, "https://app.example.test/callback")
    for redirect in (
        "https://app.example.test/callback/",
        "https://evil.example/callback",
        "https://app.example.test/callback?next=https://evil.example",
    ):
        assert not validate_client_redirect(client, redirect)
    with pytest.raises(ValueError, match="openid"):
        _ = OIDCClient(
            client_id="bad", redirect_uris=("https://app.test/cb",), scopes=("profile",)
        )


def test_authorization_code_is_bound_to_client_redirect_and_pkce() -> None:
    code = AuthorizationCode.issue(
        client_id="app",
        redirect_uri="https://app.example.test/callback",
        subject="local-user",
        scope=("openid", "profile"),
        nonce="nonce",
        code_challenge="7w_YNF9DSfIdPf_pRjSq646_kPr-2-o9NAl16JGghdM",
        now=100,
    )
    assert (
        code.redeem(
            client_id="app",
            redirect_uri="https://app.example.test/callback",
            code_verifier="v" * 43,
            now=101,
        )
        == "local-user"
    )
    with pytest.raises(PermissionError):
        code.redeem(
            client_id="app",
            redirect_uri="https://app.example.test/callback",
            code_verifier="v" * 43,
            now=102,
        )


def test_authorization_code_rejects_wrong_binding_and_expiry() -> None:
    code = AuthorizationCode.issue(
        client_id="app",
        redirect_uri="https://app.test/cb",
        subject="u",
        scope=("openid",),
        nonce="n",
        code_challenge=create_s256_code_challenge("v" * 43),
        now=100,
    )
    for kwargs in (
        {
            "client_id": "other",
            "redirect_uri": "https://app.test/cb",
            "code_verifier": "v" * 43,
            "now": 101,
        },
        {
            "client_id": "app",
            "redirect_uri": "https://evil.test/cb",
            "code_verifier": "v" * 43,
            "now": 101,
        },
        {
            "client_id": "app",
            "redirect_uri": "https://app.test/cb",
            "code_verifier": "v" * 43,
            "now": 401,
        },
    ):
        with pytest.raises(PermissionError):
            code.redeem(**kwargs)


def test_client_implements_authlib_client_contract_without_wildcards() -> None:
    client = OIDCClient(
        client_id="public",
        redirect_uris=("https://client.example/callback",),
        scopes=("openid", "profile"),
    )

    assert client.get_client_id() == "public"
    assert client.get_default_redirect_uri() == "https://client.example/callback"
    assert client.get_allowed_scope("openid profile") == "openid profile"
    assert client.get_allowed_scope("openid email") is None
    assert client.get_allowed_scope(None) == "openid profile"
    assert client.check_endpoint_auth_method("none", "token")
    assert not client.check_endpoint_auth_method("client_secret_basic", "token")
    assert client.check_response_type("code")
    assert client.check_grant_type("authorization_code")
    assert not client.check_grant_type("password")


def test_authorization_code_store_consumes_atomically_and_retains_nonce_replay() -> (
    None
):
    verifier = "v" * 43
    store = MemoryAuthorizationCodeStore(now=lambda: 100)
    code = AuthorizationCode.issue(
        client_id="app",
        redirect_uri="https://client.example/callback",
        subject="user-1",
        scope=("openid",),
        nonce="nonce-1",
        code_challenge=create_s256_code_challenge(verifier),
        now=100,
    )
    store.save(code)

    consumed = store.consume(
        code.value,
        client_id="app",
        redirect_uri="https://client.example/callback",
        code_verifier=verifier,
        now=101,
    )

    assert consumed.subject == "user-1"
    assert store.get(code.value, client_id="app") is None
    assert store.has_nonce("app", "nonce-1", now=101)
    with pytest.raises(PermissionError):
        store.consume(
            code.value,
            client_id="app",
            redirect_uri="https://client.example/callback",
            code_verifier=verifier,
            now=102,
        )


def test_memory_token_store_only_resolves_active_bearer_tokens() -> None:
    store = MemoryTokenStore()
    record = store.save(
        {
            "access_token": "secret-access-token",
            "token_type": "Bearer",
            "scope": "openid profile",
            "expires_in": 60,
        },
        client_id="app",
        subject="user-1",
        now=100,
    )

    assert record.get_scope() == "openid profile"
    assert store.get_access_token("secret-access-token", now=101) == record
    assert store.get_access_token("not-an-id-token", now=101) is None
    assert store.revoke_access_token("secret-access-token")
    assert store.get_access_token("secret-access-token", now=101) is None
