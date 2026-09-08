from my_auth import (
    SQLiteCredentialStore,
    assert_external_transaction_contract,
    ensure_sqlite_schema,
)


def test_sqlite_credential_store_supports_external_transactions() -> None:
    assert_external_transaction_contract(
        store_factory=lambda conn: SQLiteCredentialStore(
            conn, transaction_mode="external"
        ),
        schema_initializer=ensure_sqlite_schema,
    )
