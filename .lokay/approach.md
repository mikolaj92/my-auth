# Approach plan

<!-- lokay-approach source=deterministic repo=mikolaj92/my-auth issue=96 -->

Repository: `mikolaj92/my-auth`  
Issue: #96 — Cleanup: README: host composition = install_identity_adapters (nie install_passkey_ui)

## Goal

README ma prowadzić hosty do **app-factory `install_identity_adapters` + `PasskeyBinding`**. Przykład bezpośredniego `install_app_factory_ui` + `install_passkey_ui` usunąć lub przenieść do krótkiej notki „internal adapter API / library tests only”.

## Files likely touched

- `app_factory.adapters`
- `README.md`
- `app-factory/COMPAT.md`
- `examples/multi_user_bom/app.py`
- `tests/test_fastapi_htmx_adapter.py`

## Test plan

- Główny HTMX integration snippet używa `PasskeyBinding` + `install_identity_adapters` (z `app_factory.adapters`).
- Jawne: hosty **nie** wołają `install_passkey_ui` / nie kopiują installer glue.
- `install_passkey_ui` może pozostać jako API pakietu (używane przez app-factory adapter), ale nie jako host recipe.
- `rg 'install_passkey_ui' README.md` — co najwyżej w sekcji internal; host recipe = 0.
- Istniejące adapter testy nadal zielone: `uv run pytest tests/test_fastapi_htmx_adapter.py -q`.

## Non-goals

- Usuwanie `install_passkey_ui` z kodu.
- Pin bump (MA-1).

## Notes

- Trust intentional issue; this plan is evidence for later review, not a human gate.
- Coding agent may refine details but should stay on the stated goal and non-goals.
- Collector boundary: if implementation introduces unbounded collection, ship only a bounded collector patch that starts durably in the background after merge. The coding agent and lokay must not populate data or wait for collection to finish.
