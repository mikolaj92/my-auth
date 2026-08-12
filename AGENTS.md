# AGENTS.md

## Composition

Non-negotiable for this repo:

1. Prefer small Unix-style modules/processes and compose them.
2. Multi-step flows use Fala when needed; multiple Fala journals OK; nested Fala OK.
3. `my-auth` stays the auth domain library — do not re-implement product orchestration, document pipelines, or Argus/Temida chrome inside this repo.
4. Consumers (Argus/Hermes/app-factory) compose auth via BOM pins; keep this package focused.
