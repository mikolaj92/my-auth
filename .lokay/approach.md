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
- Extra stays the 0.4.x range (`app-factory[fastapi]>=0.5`). Do not pin 0.5.

## Files likely touched

- `pyproject.toml` — version 0.4.3; uv.sources tag v0.6.5
- `uv.lock` — relock app-factory to v0.6.5
- `README.md` — document the test pin / COMPAT.md tag
- `tests/test_fastapi_htmx_adapter.py` — pin assertion

## Test plan

- `uv lock --check`
- `uv run --frozen pytest tests/test_fastapi_htmx_adapter.py`

## Non-goals

- Do not land this on main 0.5.0 or change 0.5.x source.
- Do not pin the published `fastapi-htmx` extra to app-factory 0.5.x or my-auth 0.5.
- No adapter/UI/schema behavior changes.

## Notes

- Deterministic localize matched auth sources; inspection shows this is a
  packaging pin on the 0.4.x line. File list refined accordingly.
- Trust intentional issue; this plan is evidence for later review, not a human gate.
- Collector boundary: if implementation introduces unbounded collection, ship only a bounded collector patch that starts durably in the background after merge. The coding agent and mill must not populate data or wait for collection to finish.
