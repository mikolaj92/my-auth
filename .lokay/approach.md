# Approach plan

<!-- lokay-approach source=deterministic repo=mikolaj92/my-auth issue=61 -->

Repository: `mikolaj92/my-auth`  
Issue: #61 — Linia 0.4.x gniazduje app-factory v0.6.3, BOM jest v0.6.5

## Goal

BOM chrome to app-factory **v0.6.5**. Tag **v0.4.2** nadal gniazduje v0.6.3, więc sam kit testuje się na starym chrome.

## Files likely touched

- `pyproject.toml` — `[tool.uv.sources]` app-factory tag `v0.6.5`
- `uv.lock` — relock the test pin
- `README.md` — document the HTMX test chrome tag
- `tests/test_fastapi_htmx_adapter.py` — pin/lock contract

Keep package version on **0.4.x** (currently 0.4.4). Do not advertise 0.5.x.
`fastapi-htmx` extra stays `app-factory[fastapi]>=0.5`.

## Test plan

- `uv lock --upgrade-package app-factory`
- `pytest tests/test_fastapi_htmx_adapter.py tests/test_fastapi_adapter.py`

## Non-goals

- Do not mix main 0.5.0 / 0.5.x packaging
- Do not rewrite product orchestration, document pipelines, or chrome inside my-auth

## Notes

- Trust intentional issue; this plan is evidence for later review, not a human gate.
- Coding agent may refine details but should stay on the stated goal and non-goals.
- Collector boundary: if implementation introduces unbounded collection, ship only a bounded collector patch that starts durably in the background after merge. The coding agent and mill must not populate data or wait for collection to finish.
- No explicit file paths in issue; infer from repo inspection.
