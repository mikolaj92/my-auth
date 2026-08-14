# Approach plan

<!-- lokay-approach source=deterministic repo=mikolaj92/my-auth issue=63 -->

Repository: `mikolaj92/my-auth`  
Issue: #63 — main instaluje 0.5.0, BOM zakazuje 0.5.x

## Goal

Stop advertising the forbidden 0.5.x line from main. COMPAT/BOM keep my-auth 0.4.x and must not mix 0.5.x. Untagged `uv add` from main currently installs `version = "0.5.0"`.

## Files likely touched

- `pyproject.toml` — restamp package as 0.4.4 (0.4.x; avoid colliding with 0.4.3 on the v0.4.2 maintenance line)
- `uv.lock` — keep local package version in lock with pyproject
- `README.md` — pin install examples to tag `v0.4.2`; document `>=0.4,<0.5`; align chrome pin docs to `v0.5.21`
- `tests/test_fastapi_adapter.py` — fail closed if package/docs drift back to 0.5.x or untagged main install

## Test plan

- `uv lock --check`
- `uv run --frozen pytest tests/test_fastapi_adapter.py tests/test_fastapi_htmx_adapter.py`

## Non-goals

- Do not change adapter/schema/UI behavior.
- Do not mix this with #61 (0.4.2 → app-factory v0.6.5 on the maintenance line) or #62 (`initialize()`).
- Keep the repository chrome pin at app-factory `v0.5.21`.

## Notes

- Trust intentional issue; this plan is evidence for later review, not a human gate.
- Coding agent may refine details but should stay on the stated goal and non-goals.
- Collector boundary: if implementation introduces unbounded collection, ship only a bounded collector patch that starts durably in the background after merge. The coding agent and mill must not populate data or wait for collection to finish.
