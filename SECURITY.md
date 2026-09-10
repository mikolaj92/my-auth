# Security policy

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/mikolaj92/my-auth/security/advisories/new).
Private reporting is enabled for this repository. Include the affected tag/commit,
a minimal reproduction, impact, and any known mitigation. Do not put credentials,
capability tokens, or unredacted production data in a public issue.

## Scope

my-auth owns WebAuthn options and verification, RP/origin configuration,
single-use challenges, credential ownership and counters, enrollment
capabilities, and the optional pre-ceremony rate-limit hook. The host owns
rate-limit keys, trusted proxy policy, quotas, failure mode, and shared
multi-worker storage. Application sessions, CSRF policy, administrator
permissions,
provisioning, recovery authorization, and audit policy belong to the host.
The passkey HTTP/UI adapters are a WebAuthn relying party, not the OIDC surface.
The optional [minimal OpenID Provider](docs/oidc-provider.md) is implemented
behind `my-auth[oidc]`. A generic relying party uses discovery, authorization-code
+ S256 PKCE, JWKS, and UserInfo; it is not a claim of OpenID Foundation
certification or full OIDC Core support. Hosts must use HTTPS issuer/redirect
configuration, durable protected signing keys, a trusted client registry,
explicit consent/session hooks, and the documented support matrix. Do not expose
`MemorySigningKeyStore` in production. The optional passkey
Conditional UI is browser enhancement only: its username field is not an
identity assertion, and manual/hybrid login remains available. It is disabled
by default; hosts explicitly opt in with `PasskeyUiConfig(conditional_ui=True)`. Future protocol,
client validation, token issuance and key-management vulnerabilities belong in
this repository's private reporting channel.

## Versions and support

This is pre-1.0 software. The package version is recorded in `pyproject.toml`;
[CHANGELOG.md](CHANGELOG.md) distinguishes tagged changes from unreleased work.
Use the tested identity combination in the
[app-factory compatibility matrix](https://github.com/mikolaj92/app-factory/blob/main/COMPAT.md).

Reports should identify the exact version. There is currently no promised
response-time SLA or blanket backport guarantee for older branches. Maintainers
will state affected versions, fixes, and any backports in the relevant advisory.
This policy does not declare older tags safe or silently mark them end-of-life.
