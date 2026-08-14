# Approach plan

<!-- lokay-approach source=deterministic repo=mikolaj92/my-auth issue=62 -->

Repository: `mikolaj92/my-auth`  
Issue: #62 — initialize() nie dokłada additive DDL na istniejącej bazie

## Goal

`SQLiteAuthDatabase.initialize()` woła `ensure_sqlite_schema` tylko na empty/unversioned. Na `current` pomija additive DDL (`passkey_enrollment_capabilities`). Argus omija to drugim `ensure_sqlite_schema` po initialize().

## Files likely touched

- `src/my_auth/sqlite_schema.py` — apply additive enrollment DDL on `current`
- `src/my_auth/enrollment.py` — share the canonical capability DDL
- `tests/test_enrollment_capabilities.py` — cover ensure on existing current DBs

## Test plan

- `pytest tests/test_enrollment_capabilities.py tests/test_v02_contracts.py tests/test_store_contracts.py tests/test_registration_context.py -q`

## Non-goals

- (none stated)

## Notes

- Trust intentional issue; this plan is evidence for later review, not a human gate.
- Coding agent may refine details but should stay on the stated goal and non-goals.
- Collector boundary: if implementation introduces unbounded collection, ship only a bounded collector patch that starts durably in the background after merge. The coding agent and mill must not populate data or wait for collection to finish.
- No explicit file paths in issue; infer from repo inspection.
