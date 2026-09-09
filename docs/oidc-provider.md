# Decision: my-auth is the OpenID Provider

## Direction and current status

The owner explicitly approved implementing the **provider/server** side of OIDC
in my-auth. Earlier plans to use Keycloak as the application's provider were a
misinterpretation and are superseded. No external identity server is required.
The existing released package is still a WebAuthn relying party, NOT an OIDC
provider. This decision does not assert implementation or certification.

WebAuthn RP and OpenID Provider are different roles: my-auth verifies the user's
passkey and, as OP, will authorize registered OIDC clients and issue tokens.

## Ownership

- my-auth: optional OIDC protocol/server modules, registered clients, exact
  redirect validation, grants, authorization codes, token issuance, keys/JWKS,
  discovery, UserInfo, provider-session and consent mechanics.
- my-usermanager: stable users, current account status, claims projection and
  local grants. No automatic translation of client scopes into administrator
  permissions, and no second user directory in my-auth.
- app-factory: shared shells and composition of packaged identity pages. No
  protocol implementation or product-specific workflow in chrome.
- host: configured issuer, key storage, trusted clients, deployment, consent and
  claim-release policy, account provisioning and session/recovery policy.

Use Authlib's authorization-server/OIDC grants and maintained JOSE primitives;
do not implement cryptography or fork protocol validation into product apps.
Optional imports must not make the existing passkey core require an OIDC stack.

## Delivery gates (not claims of current support)

1. **Protocol seam and clients:** explicit issuer, immutable client metadata,
   exact redirect matching, allowed scopes/response types/auth methods, errors
   that never redirect to unvalidated targets. Test before protocol handlers.
2. **Authorization Code + S256 PKCE:** integrate the existing verified passkey
   session; consent, state echo, nonce, prompt/max_age, error behavior; short-lived
   one-time codes bound to client, redirect, subject and PKCE. Atomic redemption.
3. **Tokens and keys:** Authlib-backed token endpoint, client authentication,
   ID-token claims, signature/algorithm restrictions, durable signing keys,
   public-only JWKS, key rotation, bounded token lifetimes. No secrets in logs.
4. **Discovery and UserInfo:** advertise only functioning capabilities; issuer
   consistency, scope-based claims, access-token validation and token-type
   separation. Discovery includes `claims_supported`, `claim_types_supported`,
   and explicit false request-object flags so a generic RP can complete the
   authorization-code + S256 PKCE flow from metadata alone. Never accept an ID
   token as an API access token.
5. **Lifecycle:** explicit refresh-token/offline-access policy, revocation,
   provider-session handling and separately specified logout extensions.
6. **Composition:** runnable my-auth + UM + app-factory host, standard independent
   OIDC client, actual passkey browser login, local account/disabled checks.
7. **Conformance:** record selected OpenID Foundation OP test-plan identifiers,
   versions, configuration and complete results. Negative/replay/concurrency and
   rotation tests run in CI. No release claim of full compliance from a smoke.

## Meaning of full compliance

Maintain an explicit support matrix against OIDC Core and each chosen extension.
Authorization Code is the first vertical slice, not the definition of completion.
Assess additional response types, response modes, subject types, client auth,
registration, request objects and logout against their normative requirements
and security guidance. Optional features must be marked supported, unsupported
or planned rather than silently implied. Certification is a separate claim,
made only after the applicable OpenID Foundation process is completed.

Sources:
- https://openid.net/specs/openid-connect-core-1_0.html
- https://openid.net/specs/openid-connect-discovery-1_0.html
- https://openid.net/certification/
- https://docs.authlib.org/en/latest/oauth2/server.html
- https://docs.authlib.org/en/latest/oidc/core/grants.html
