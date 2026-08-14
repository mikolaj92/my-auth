from __future__ import annotations

import hashlib
import sqlite3
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from my_auth import (
    EnrollmentCapabilityNotFound,
    EnrollmentCapabilityStore,
    EnrollmentPurpose,
    MemoryEnrollmentCapabilityStore,
    SQLiteEnrollmentCapabilityStore,
    ensure_sqlite_schema,
    inspect_sqlite_schema,
)


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value


def assert_capability_contract(
    factory: Callable[[Callable[[], datetime]], EnrollmentCapabilityStore],
) -> None:
    clock = Clock()
    store = factory(clock)
    issued = store.issue(
        subject="user-1",
        purpose="invitation",
        ttl_seconds=300,
        issued_by="admin-1",
    )
    assert issued.token not in repr(issued)
    assert issued.capability.subject == "user-1"
    assert issued.capability.issued_by == "admin-1"

    claimed = store.claim(
        token=issued.token,
        flow_id="flow-1",
        expected_purpose="invitation",
    )
    assert claimed.subject == "user-1"
    assert claimed.claimed_flow_id == "flow-1"
    assert store.claim(
        token=issued.token,
        flow_id="flow-1",
        expected_purpose="invitation",
    ) == claimed

    with pytest.raises(EnrollmentCapabilityNotFound):
        store.claim(
            token=issued.token,
            flow_id="other-flow",
            expected_purpose="invitation",
        )
    with pytest.raises(EnrollmentCapabilityNotFound):
        store.claim(
            token=issued.token,
            flow_id="flow-1",
            expected_purpose="account_recovery",
        )

    consumed = store.consume(flow_id="flow-1")
    assert consumed.subject == "user-1"
    assert consumed.consumed_at is not None
    with pytest.raises(EnrollmentCapabilityNotFound):
        store.consume(flow_id="flow-1")
    with pytest.raises(EnrollmentCapabilityNotFound):
        store.claim(
            token=issued.token,
            flow_id="flow-1",
            expected_purpose="invitation",
        )
    assert store.release(flow_id="flow-1") is False
    assert store.revoke(issued.capability.capability_id) is False

    releasable = store.issue(
        subject="user-2", purpose="account_recovery", ttl_seconds=300
    )
    store.claim(
        token=releasable.token,
        flow_id="release-flow",
        expected_purpose="account_recovery",
    )
    assert store.release(flow_id="release-flow") is True
    assert store.claim(
        token=releasable.token,
        flow_id="replacement-flow",
        expected_purpose="account_recovery",
    ).subject == "user-2"

    revoked = store.issue(
        subject="user-3", purpose="invitation", ttl_seconds=300
    )
    assert store.revoke(revoked.capability.capability_id) is True
    assert store.revoke(revoked.capability.capability_id) is False
    with pytest.raises(EnrollmentCapabilityNotFound):
        store.claim(
            token=revoked.token,
            flow_id="revoked-flow",
            expected_purpose="invitation",
        )

    expired = store.issue(
        subject="user-4", purpose="invitation", ttl_seconds=1
    )
    clock.value += timedelta(seconds=2)
    with pytest.raises(EnrollmentCapabilityNotFound):
        store.claim(
            token=expired.token,
            flow_id="expired-flow",
            expected_purpose="invitation",
        )

    with pytest.raises(EnrollmentCapabilityNotFound):
        store.claim(
            token="unknown-token",
            flow_id="unknown-flow",
            expected_purpose="invitation",
        )


def test_memory_capability_store_contract() -> None:
    assert_capability_contract(lambda now: MemoryEnrollmentCapabilityStore(now=now))


def test_sqlite_capability_store_contract(tmp_path: Path) -> None:
    database = tmp_path / "capabilities.sqlite3"
    assert_capability_contract(
        lambda now: SQLiteEnrollmentCapabilityStore(database, now=now)
    )


def test_sqlite_persists_only_a_hash_of_the_bearer_token(tmp_path: Path) -> None:
    database = tmp_path / "capabilities.sqlite3"
    store = SQLiteEnrollmentCapabilityStore(database)
    issued = store.issue(
        subject="user-1", purpose="account_recovery", ttl_seconds=60
    )
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT token_hash FROM passkey_enrollment_capabilities"
        ).fetchone()
    assert row is not None
    assert issued.token not in str(row[0])
    expected = hashlib.sha256(
        b"my-auth:enrollment-capability:v1\0" + issued.token.encode()
    ).hexdigest()
    assert row[0] == expected


@pytest.mark.parametrize(
    ("subject", "purpose", "ttl_seconds", "issued_by"),
    [
        ("", "invitation", 60, None),
        (" user ", "invitation", 60, None),
        ("user", "other", 60, None),
        ("user", "invitation", 0, None),
        ("user", "invitation", 60, " admin "),
    ],
)
def test_issue_rejects_invalid_input(
    subject: str, purpose: str, ttl_seconds: int, issued_by: str | None
) -> None:
    store = MemoryEnrollmentCapabilityStore()
    with pytest.raises(ValueError):
        store.issue(
            subject=subject,
            purpose=cast(EnrollmentPurpose, purpose),
            ttl_seconds=ttl_seconds,
            issued_by=issued_by,
        )


def test_memory_claim_has_one_concurrent_winner() -> None:
    store = MemoryEnrollmentCapabilityStore()
    issued = store.issue(subject="user", purpose="invitation", ttl_seconds=60)
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def claim(flow_id: str) -> None:
        barrier.wait()
        try:
            store.claim(
                token=issued.token,
                flow_id=flow_id,
                expected_purpose="invitation",
            )
        except EnrollmentCapabilityNotFound:
            outcomes.append("unavailable")
        else:
            outcomes.append("claimed")

    threads = [threading.Thread(target=claim, args=(flow,)) for flow in ("a", "b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["claimed", "unavailable"]


def test_sqlite_claim_has_one_concurrent_winner(tmp_path: Path) -> None:
    database = tmp_path / "concurrent.sqlite3"
    store = SQLiteEnrollmentCapabilityStore(database)
    issued = store.issue(subject="user", purpose="invitation", ttl_seconds=60)
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def claim(flow_id: str) -> None:
        worker = SQLiteEnrollmentCapabilityStore(database)
        barrier.wait()
        try:
            worker.claim(
                token=issued.token,
                flow_id=flow_id,
                expected_purpose="invitation",
            )
        except EnrollmentCapabilityNotFound:
            outcomes.append("unavailable")
        else:
            outcomes.append("claimed")

    threads = [threading.Thread(target=claim, args=(flow,)) for flow in ("a", "b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["claimed", "unavailable"]


def _table_names(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }


def test_ensure_sqlite_schema_creates_enrollment_capabilities_table() -> None:
    connection = sqlite3.connect(":memory:")
    ensure_sqlite_schema(connection)
    assert "passkey_enrollment_capabilities" in _table_names(connection)
    columns = {
        str(row[1])
        for row in connection.execute(
            "PRAGMA table_info(passkey_enrollment_capabilities)"
        )
    }
    assert columns == {
        "capability_id",
        "token_hash",
        "purpose",
        "subject",
        "expires_at",
        "issued_by",
        "claimed_flow_id",
        "claimed_at",
        "consumed_at",
        "revoked_at",
    }
    indexes = {
        str(row[1])
        for row in connection.execute(
            "PRAGMA index_list(passkey_enrollment_capabilities)"
        )
    }
    assert "idx_passkey_enrollment_capabilities_expires_at" in indexes
    inspection = inspect_sqlite_schema(connection)
    assert inspection.state == "current"
    assert inspection.version == 3
    connection.close()


def test_ensure_stamps_enrollment_table_on_existing_current_schema() -> None:
    connection = sqlite3.connect(":memory:")
    ensure_sqlite_schema(connection)
    connection.execute("DROP TABLE passkey_enrollment_capabilities")
    connection.commit()
    assert inspect_sqlite_schema(connection).state == "current"
    assert "passkey_enrollment_capabilities" not in _table_names(connection)
    ensure_sqlite_schema(connection)
    assert "passkey_enrollment_capabilities" in _table_names(connection)
    assert inspect_sqlite_schema(connection).state == "current"
    connection.close()
