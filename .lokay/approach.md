# Approach plan

<!-- lokay-approach source=deterministic repo=mikolaj92/my-auth issue=61 -->

Repository: `mikolaj92/my-auth`  
Issue: #61 — Linia 0.4.x gniazduje app-factory v0.6.3, BOM jest v0.6.5

## Goal

BOM chrome is app-factory **v0.6.5**. Tag **v0.4.2** still nests v0.6.3, so
the kit tests itself on stale chrome.

Fail-closed:
- Branch from tag **v0.4.2**, package version **0.4.3**. Do not mix with main 0.5.0.
- `[tool.uv.sources]` app-factory → tag **v0.6.5**. Relock. Tests pass.
- Extra stays `my-auth` 0.4.x. Do not pin 0.5.

## Files likely touched

- `pyproject.toml` — version 0.4.3; app-factory source tag v0.6.5
- `uv.lock` — resolve app-factory v0.6.5 and local package 0.4.3
- `README.md` — document the v0.6.5 test pin and COMPAT link
- `tests/test_fastapi_htmx_adapter.py` — pin contract asserts v0.6.5

## Test plan

- `uv lock --check`
- `uv run --frozen pytest tests/test_fastapi_htmx_adapter.py`
- Full `uv run --frozen pytest` if the pin test and lock check pass

## Non-goals

- Do not mix 0.5.0 / main adapter or schema changes.
- Do not change the published extra (`app-factory[fastapi]>=0.5`).
- Do not pin hosts to my-auth 0.5.

## Notes

- Inspection refined the localize list: Agentless seed matched 0.5.0 adapter
  sources on main. The issue is 0.4.x packaging only.
- Closed PR #60 already landed the same packaging patch on
  `cursor/packaging-0.4.3-app-factory-v0.6.5-7c3d` (not merged; closed to
  re-run through the mill as this issue).
