# Approach plan

<!-- lokay-approach source=deterministic repo=mikolaj92/my-auth issue=61 -->

Repository: `mikolaj92/my-auth`  
Issue: #61 — Linia 0.4.x gniazduje app-factory v0.6.3, BOM jest v0.6.5

## Goal

BOM chrome is app-factory **v0.6.5**. Tag **v0.4.2** still nests v0.6.3, so the
0.4.x kit tests against stale chrome.

Fail-closed:

- Branch from tag **v0.4.2**, package version **0.4.3**. Do not mix with main 0.5.0.
- `[tool.uv.sources]` app-factory → tag **v0.6.5**. Relock. Tests pass.
- Extra stays `my-auth` 0.4.x. Do not pin my-auth 0.5.

## Files likely touched

- `pyproject.toml` — version 0.4.3; `tool.uv.sources.app-factory` tag `v0.6.5`
- `uv.lock` — relock app-factory to v0.6.5
- `README.md` — documented test pin / COMPAT.md link
- `tests/test_fastapi_htmx_adapter.py` — pin-lock contract assertions

Packaging only. No source/API changes on the 0.4.x line.

## Test plan

- `uv lock` / lock contract test
- `tests/test_fastapi_htmx_adapter.py::test_repository_app_factory_pin_matches_lock`
- targeted HTMX adapter tests after relock

## Non-goals

- Do not restamp main 0.5.0 as this release.
- Do not change the published `fastapi-htmx` extra range (`app-factory[fastapi]>=0.5`).
- Do not implement product orchestration or mix 0.5.0 source into 0.4.3.

## Notes

- Trust intentional issue; this plan is evidence for later review, not a human gate.
- Coding agent may refine details but should stay on the stated goal and non-goals.
- Collector boundary: if implementation introduces unbounded collection, ship only a bounded collector patch that starts durably in the background after merge. The coding agent and mill must not populate data or wait for collection to finish.
- Localize listed adapter sources; inspection showed a packaging-only pin on v0.4.2.
