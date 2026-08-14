# Approach plan

<!-- lokay-approach source=deterministic repo=mikolaj92/my-auth issue=61 -->

Repository: `mikolaj92/my-auth`  
Issue: #61 — Linia 0.4.x gniazduje app-factory v0.6.3, BOM jest v0.6.5

## Goal

BOM chrome is app-factory **v0.6.5**. Tag **v0.4.2** still nests v0.6.3, so
the 0.4.x kit tests against stale chrome.

Fail-closed:
- Branch from tag **v0.4.2**, package version **0.4.3**. Do not mix with main 0.5.0.
- `[tool.uv.sources]` app-factory → tag **v0.6.5**. Relock. Tests pass.
- Extra stays `my-auth` 0.4.x (`app-factory[fastapi]>=0.5`). Do not pin 0.5.

## Files likely touched

- `pyproject.toml` — version 0.4.3; uv.sources tag v0.6.5
- `uv.lock` — relock app-factory to v0.6.5
- `README.md` — documented test pin
- `tests/test_fastapi_htmx_adapter.py` — pin/lock assertion

## Test plan

- `uv lock --check`
- `uv run --frozen pytest tests/test_fastapi_htmx_adapter.py`

## Non-goals

- No 0.5.0 / main mix.
- No extra pin to 0.5.x.
- No product/auth logic changes.

## Notes

- Deterministic localize listed the 0.4.2 source tree; inspection showed this
  is a packaging-only pin bump on the 0.4.x line.
- Trust intentional issue; this plan is evidence for later review, not a human gate.
