# Security policy

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/mikolaj92/my-auth/security/advisories/new).
Private reporting is enabled for this repository. Include the affected tag/commit,
a minimal reproduction, impact, and any known mitigation. Do not put credentials,
capability tokens, or unredacted production data in a public issue.

## Scope

my-auth owns WebAuthn options and verification, RP/origin configuration,
single-use challenges, credential ownership and counters, and enrollment
capabilities. Application sessions, CSRF policy, administrator permissions,
provisioning, recovery authorization, and audit policy belong to the host.
The existing HTTP/UI adapters are not an OAuth/OIDC provider. The approved
[OIDC provider direction](docs/oidc-provider.md) adds optional server-side
protocol support in my-auth, not a dependency on an external identity server.
The first provider profile is now implemented behind `my-auth[oidc]`; it is not a
claim of OpenID Foundation certification or full OIDC Core support. Hosts must
use HTTPS issuer/redirect configuration, durable protected signing keys, a
trusted client registry, explicit consent/session hooks, and the documented
support matrix. Do not expose `MemorySigningKeyStore` in production. Future
protocol, client validation, token issuance and key-management vulnerabilities
belong in this repository's private reporting channel.

## Versions and support

This is pre-1.0 software. The package version is recorded in `pyproject.toml`;
[CHANGELOG.md](CHANGELOG.md) distinguishes tagged changes from unreleased work.
Use the tested identity combination in the
[app-factory compatibility matrix](https://github.com/mikolaj92/app-factory/blob/main/COMPAT.md).

Reports should identify the exact version. There is currently no promised
response-time SLA or blanket backport guarantee for older branches. Maintainers
will state affected versions, fixes, and any backports in the relevant advisory.
This policy does not declare older tags safe or silently mark them end-of-life.
