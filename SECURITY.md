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
Optional HTTP/UI adapters do not turn this library into an OAuth/OIDC provider.

## Versions and support

This is pre-1.0 software. The package version is recorded in `pyproject.toml`;
[CHANGELOG.md](CHANGELOG.md) distinguishes tagged changes from unreleased work.
Use the tested identity combination in the
[app-factory compatibility matrix](https://github.com/mikolaj92/app-factory/blob/main/COMPAT.md).

Reports should identify the exact version. There is currently no promised
response-time SLA or blanket backport guarantee for older branches. Maintainers
will state affected versions, fixes, and any backports in the relevant advisory.
This policy does not declare older tags safe or silently mark them end-of-life.
