# AGENTS.md

## Composition

Non-negotiable for this repo:

1. Prefer small Unix-style modules/processes and compose them.
2. Multi-step flows use Fala when needed; multiple Fala journals OK; nested Fala OK.
3. `my-auth` is a minimal OpenID Provider plus the passkey WebAuthn RP behind it. Do not grow it into Keycloak, product orchestration, document pipelines, or Argus/Temida chrome. Keep the OIDC profile swappable: advertise only what a generic RP can also get from another OP.
4. Consumers (Argus/Hermes/app-factory) compose auth via BOM pins; keep this package focused.
