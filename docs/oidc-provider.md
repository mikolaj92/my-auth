# my-auth is a minimal OpenID Provider

A host application talks to my-auth the same way it talks to any other OpenID
Provider: discovery, authorization-code + S256 PKCE, JWKS, ID token, and
UserInfo. Passkeys stay behind that protocol. When the host outgrows this
profile, it swaps the issuer URL — not the product domain, local `user_id`, or
grants.

This is one FastAPI application, not a second process. The OP is
`build_oidc_fastapi_plugin` on the same origin as `/login` and `/oidc/callback`.
Unauthenticated authorize redirects to the host `login_url` with a same-origin
`next` path; `prompt=none` still returns `login_required` to the client.
No Keycloak, extra port, or extra server is required for the local profile.

This is not a certified OP and not a proxy for arbitrary identity workflows.
The passkey core (`import my_auth`) stays usable without Authlib. The provider
is the optional `my-auth[oidc]` extra.

## Shipped profile

| Surface | Support |
|---|---|
| Discovery | `/.well-known/openid-configuration` advertises only this profile |
| Authorization | `response_type=code`; `openid` scope, `nonce`, and S256 PKCE required. No session → same-origin `login_url` (optional). `prompt=none` → client `login_required` |
| Token | `grant_type=authorization_code` only; one-time codes bound to client, redirect, subject, PKCE |
| ID token | RS256, public JWKS, `kid`; never accept an ID token as an API access token |
| UserInfo | Bearer access token in the Authorization header or POST body; claims filtered by granted `openid` / `profile` / `email`; 401 includes RFC 6750 `WWW-Authenticate` `error` |
| Clients | Immutable registered clients; exact HTTPS redirects; `none` or `client_secret_basic` |
| Subjects | `public` only |

Discovery includes `claims_supported`, `claim_types_supported: ["normal"]`, and
explicit `request_parameter_supported` / `request_uri_parameter_supported` false
so a generic relying party can complete the flow from metadata alone.

WebAuthn RP and OpenID Provider are different roles in the same package: my-auth
verifies the user's passkey and, as OP, authorizes registered OIDC clients and
issues tokens from that already-authenticated session.

## Out of scope for this profile

Do not advertise or implement these, and do not let a host depend on them if it
must remain swappable onto my-auth:

- refresh tokens / `offline_access`
- implicit, hybrid, or password grants
- `client_secret_post`, HS256, `alg=none`
- dynamic client registration
- request objects / `request_uri`
- RP-Initiated, session, front-channel, or back-channel logout
- pairwise subjects
- OpenID Foundation certification

Revocation is optional and public-client only. It is not full RFC 7009.

Passing the included tests is not certification.

## Ownership

- my-auth: optional OIDC protocol/server modules, registered clients, exact
  redirect validation, grants, authorization codes, token issuance, keys/JWKS,
  discovery, UserInfo, and host session/consent seams.
- my-usermanager: stable users, current account status, claims projection and
  local grants. No automatic translation of client scopes into administrator
  permissions, and no second user directory in my-auth.
- app-factory: shared shells and composition of packaged identity pages. No
  protocol implementation or product-specific workflow in chrome.
- host: configured issuer, durable signing keys, trusted clients, deployment,
  consent and claim-release policy, account provisioning, and session/recovery
  policy. Production must not use `MemorySigningKeyStore`.

Use Authlib's authorization-server/OIDC grants and maintained JOSE primitives;
do not implement cryptography or fork protocol validation into product apps.
Optional imports must not make the existing passkey core require an OIDC stack.

## Remaining proof (not extra protocol)

The in-process profile is implemented: one app can be both OP and RP. What is
still required for the product contract is a host that logs in only as a generic
relying party against this issuer, then against another OP (for example
Keycloak), with the same local `user_id` and grants. That proof lives in
my-usermanager, not in growing this profile or adding a second server.

Sources:
- https://openid.net/specs/openid-connect-core-1_0.html
- https://openid.net/specs/openid-connect-discovery-1_0.html
- https://docs.authlib.org/en/latest/oauth2/server.html
- https://docs.authlib.org/en/latest/oidc/core/grants.html
