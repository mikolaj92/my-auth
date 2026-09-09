import sqlite3

import pytest

from my_auth import (
    SQLiteCredentialStore,
    VerifiedRegistration,
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


def test_contract_rejects_hidden_commit() -> None:
    class CommittingStore(SQLiteCredentialStore):
        def __init__(self, connection: sqlite3.Connection) -> None:
            super().__init__(connection, transaction_mode="external")
            self.connection = connection

        def save_registration(self, result: VerifiedRegistration) -> None:
            super().save_registration(result)
            self.connection.commit()

    with pytest.raises(AssertionError, match="committed"):
        assert_external_transaction_contract(CommittingStore, ensure_sqlite_schema)


def test_contract_detects_damage_to_shared_host_transaction() -> None:
    class HostRecordDeletingStore(SQLiteCredentialStore):
        def __init__(self, connection: sqlite3.Connection) -> None:
            super().__init__(connection, transaction_mode="external")
            self.connection = connection

        def save_registration(self, result: VerifiedRegistration) -> None:
            super().save_registration(result)
            table = self.connection.execute(
                "SELECT name FROM sqlite_master WHERE name='_contract_host_records'"
            ).fetchone()
            if table:
                self.connection.execute("DELETE FROM _contract_host_records")

    with pytest.raises(AssertionError):
        assert_external_transaction_contract(
            HostRecordDeletingStore, ensure_sqlite_schema
        )
