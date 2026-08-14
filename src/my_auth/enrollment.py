from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol, cast

from .sqlite_schema import PASSKEY_ENROLLMENT_CAPABILITY_SCHEMA

EnrollmentPurpose = Literal["invitation", "account_recovery"]


class EnrollmentCapabilityNotFound(Exception):
    """Raised for every unusable capability without disclosing why it failed."""


@dataclass(frozen=True)
class EnrollmentCapability:
    capability_id: str
    purpose: EnrollmentPurpose
    subject: str
    expires_at: datetime
    issued_by: str | None = None
    claimed_flow_id: str | None = None
    claimed_at: datetime | None = None
    consumed_at: datetime | None = None
    revoked_at: datetime | None = None


@dataclass(frozen=True)
class IssuedEnrollmentCapability:
    capability: EnrollmentCapability
    token: str = field(repr=False)


class EnrollmentCapabilityStore(Protocol):
    def issue(
        self,
        *,
        subject: str,
        purpose: EnrollmentPurpose,
        ttl_seconds: int,
        issued_by: str | None = None,
    ) -> IssuedEnrollmentCapability: ...

    def claim(
        self,
        *,
        token: str,
        flow_id: str,
        expected_purpose: EnrollmentPurpose,
    ) -> EnrollmentCapability: ...

    def consume(self, *, flow_id: str) -> EnrollmentCapability: ...
    def release(self, *, flow_id: str) -> bool: ...
    def revoke(self, capability_id: str) -> bool: ...


def _now_utc(now: Callable[[], datetime]) -> datetime:
    value = now()
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("now must return a timezone-aware datetime")
    return value.astimezone(UTC)


def _validate_issue(
    *, subject: str, purpose: str, ttl_seconds: int, issued_by: str | None
) -> None:
    if not subject or subject != subject.strip():
        raise ValueError("subject must be a non-empty trimmed string")
    if purpose not in {"invitation", "account_recovery"}:
        raise ValueError("unsupported enrollment capability purpose")
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    if issued_by is not None and (not issued_by or issued_by != issued_by.strip()):
        raise ValueError("issued_by must be a non-empty trimmed string")


def _validate_claim(*, token: str, flow_id: str, expected_purpose: str) -> None:
    if not token or not flow_id:
        raise EnrollmentCapabilityNotFound("enrollment capability is unavailable")
    if expected_purpose not in {"invitation", "account_recovery"}:
        raise ValueError("unsupported enrollment capability purpose")


def _token_hash(token: str) -> str:
    return hashlib.sha256(b"my-auth:enrollment-capability:v1\0" + token.encode()).hexdigest()


def _new_issued(
    *,
    subject: str,
    purpose: EnrollmentPurpose,
    ttl_seconds: int,
    issued_by: str | None,
    now: datetime,
) -> tuple[IssuedEnrollmentCapability, str]:
    token = secrets.token_urlsafe(32)
    record = EnrollmentCapability(
        capability_id=secrets.token_urlsafe(18),
        purpose=purpose,
        subject=subject,
        expires_at=now + timedelta(seconds=ttl_seconds),
        issued_by=issued_by,
    )
    return IssuedEnrollmentCapability(record, token), _token_hash(token)


class MemoryEnrollmentCapabilityStore:
    def __init__(self, *, now: Callable[[], datetime] | None = None) -> None:
        self._now = now or (lambda: datetime.now(UTC))
        self._records: dict[str, tuple[str, EnrollmentCapability]] = {}
        self._lock = threading.RLock()

    def issue(
        self,
        *,
        subject: str,
        purpose: EnrollmentPurpose,
        ttl_seconds: int,
        issued_by: str | None = None,
    ) -> IssuedEnrollmentCapability:
        _validate_issue(
            subject=subject,
            purpose=purpose,
            ttl_seconds=ttl_seconds,
            issued_by=issued_by,
        )
        issued, token_hash = _new_issued(
            subject=subject,
            purpose=purpose,
            ttl_seconds=ttl_seconds,
            issued_by=issued_by,
            now=_now_utc(self._now),
        )
        with self._lock:
            self._records[issued.capability.capability_id] = (
                token_hash,
                issued.capability,
            )
        return issued

    def claim(
        self,
        *,
        token: str,
        flow_id: str,
        expected_purpose: EnrollmentPurpose,
    ) -> EnrollmentCapability:
        _validate_claim(
            token=token, flow_id=flow_id, expected_purpose=expected_purpose
        )
        digest = _token_hash(token)
        now = _now_utc(self._now)
        with self._lock:
            match = next(
                (item for item in self._records.items() if item[1][0] == digest), None
            )
            if match is None:
                raise EnrollmentCapabilityNotFound(
                    "enrollment capability is unavailable"
                )
            capability_id, (_, record) = match
            if (
                record.purpose != expected_purpose
                or record.expires_at <= now
                or record.consumed_at is not None
                or record.revoked_at is not None
                or record.claimed_flow_id not in {None, flow_id}
            ):
                raise EnrollmentCapabilityNotFound(
                    "enrollment capability is unavailable"
                )
            if record.claimed_flow_id is None:
                record = replace(
                    record,
                    claimed_flow_id=flow_id,
                    claimed_at=now,
                )
                self._records[capability_id] = (digest, record)
            return record

    def consume(self, *, flow_id: str) -> EnrollmentCapability:
        now = _now_utc(self._now)
        with self._lock:
            match = next(
                (
                    item
                    for item in self._records.items()
                    if item[1][1].claimed_flow_id == flow_id
                ),
                None,
            )
            if match is None:
                raise EnrollmentCapabilityNotFound(
                    "enrollment capability is unavailable"
                )
            capability_id, (digest, record) = match
            if (
                record.expires_at <= now
                or record.consumed_at is not None
                or record.revoked_at is not None
            ):
                raise EnrollmentCapabilityNotFound(
                    "enrollment capability is unavailable"
                )
            record = replace(record, consumed_at=now)
            self._records[capability_id] = (digest, record)
            return record

    def release(self, *, flow_id: str) -> bool:
        with self._lock:
            match = next(
                (
                    item
                    for item in self._records.items()
                    if item[1][1].claimed_flow_id == flow_id
                ),
                None,
            )
            if match is None:
                return False
            capability_id, (digest, record) = match
            if record.consumed_at is not None or record.revoked_at is not None:
                return False
            record = replace(
                record,
                claimed_flow_id=None,
                claimed_at=None,
            )
            self._records[capability_id] = (digest, record)
            return True

    def revoke(self, capability_id: str) -> bool:
        now = _now_utc(self._now)
        with self._lock:
            stored = self._records.get(capability_id)
            if stored is None:
                return False
            digest, record = stored
            if record.consumed_at is not None or record.revoked_at is not None:
                return False
            self._records[capability_id] = (
                digest,
                replace(record, revoked_at=now),
            )
            return True


_CAPABILITY_COLUMNS = (
    "capability_id,purpose,subject,expires_at,issued_by,claimed_flow_id,"
    "claimed_at,consumed_at,revoked_at"
)


class SQLiteEnrollmentCapabilityStore:
    """Durable capability store; raw bearer tokens are never persisted."""

    def __init__(
        self,
        database: str | Path | sqlite3.Connection,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if isinstance(database, sqlite3.Connection):
            self._external: sqlite3.Connection | None = database
            self._path: Path | None = None
        else:
            self._external = None
            self._path = Path(database)
        self._now = now or (lambda: datetime.now(UTC))
        if self._path is not None and self._path.parent != Path(""):
            self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection(mutation=True) as connection:
            for statement in (
                part.strip()
                for part in PASSKEY_ENROLLMENT_CAPABILITY_SCHEMA.split(";")
                if part.strip()
            ):
                connection.execute(statement)

    @contextmanager
    def _connection(self, *, mutation: bool = False):
        if self._external is not None:
            connection = self._external
        else:
            assert self._path is not None
            connection = sqlite3.connect(
                self._path, timeout=30, check_same_thread=False
            )
        owns_transaction = mutation and not connection.in_transaction
        try:
            if owns_transaction:
                connection.execute("BEGIN IMMEDIATE")
            yield connection
            if owns_transaction:
                connection.commit()
        except Exception:
            if owns_transaction:
                connection.rollback()
            raise
        finally:
            if self._external is None:
                connection.close()

    def issue(
        self,
        *,
        subject: str,
        purpose: EnrollmentPurpose,
        ttl_seconds: int,
        issued_by: str | None = None,
    ) -> IssuedEnrollmentCapability:
        _validate_issue(
            subject=subject,
            purpose=purpose,
            ttl_seconds=ttl_seconds,
            issued_by=issued_by,
        )
        issued, token_hash = _new_issued(
            subject=subject,
            purpose=purpose,
            ttl_seconds=ttl_seconds,
            issued_by=issued_by,
            now=_now_utc(self._now),
        )
        record = issued.capability
        with self._connection(mutation=True) as connection:
            connection.execute(
                "INSERT INTO passkey_enrollment_capabilities "
                "(capability_id,token_hash,purpose,subject,expires_at,issued_by) "
                "VALUES(?,?,?,?,?,?)",
                (
                    record.capability_id,
                    token_hash,
                    record.purpose,
                    record.subject,
                    record.expires_at.isoformat(),
                    record.issued_by,
                ),
            )
        return issued

    def claim(
        self,
        *,
        token: str,
        flow_id: str,
        expected_purpose: EnrollmentPurpose,
    ) -> EnrollmentCapability:
        _validate_claim(
            token=token, flow_id=flow_id, expected_purpose=expected_purpose
        )
        now = _now_utc(self._now)
        with self._connection(mutation=True) as connection:
            row = connection.execute(
                f"UPDATE passkey_enrollment_capabilities "
                "SET claimed_flow_id=COALESCE(claimed_flow_id,?), "
                "claimed_at=COALESCE(claimed_at,?) "
                "WHERE token_hash=? AND purpose=? AND expires_at>? "
                "AND consumed_at IS NULL AND revoked_at IS NULL "
                "AND (claimed_flow_id IS NULL OR claimed_flow_id=?) "
                f"RETURNING {_CAPABILITY_COLUMNS}",
                (
                    flow_id,
                    now.isoformat(),
                    _token_hash(token),
                    expected_purpose,
                    now.isoformat(),
                    flow_id,
                ),
            ).fetchone()
        if row is None:
            raise EnrollmentCapabilityNotFound("enrollment capability is unavailable")
        return _capability_from_row(row)

    def consume(self, *, flow_id: str) -> EnrollmentCapability:
        now = _now_utc(self._now)
        with self._connection(mutation=True) as connection:
            row = connection.execute(
                f"UPDATE passkey_enrollment_capabilities SET consumed_at=? "
                "WHERE claimed_flow_id=? AND expires_at>? "
                "AND consumed_at IS NULL AND revoked_at IS NULL "
                f"RETURNING {_CAPABILITY_COLUMNS}",
                (now.isoformat(), flow_id, now.isoformat()),
            ).fetchone()
        if row is None:
            raise EnrollmentCapabilityNotFound("enrollment capability is unavailable")
        return _capability_from_row(row)

    def release(self, *, flow_id: str) -> bool:
        with self._connection(mutation=True) as connection:
            changed = connection.execute(
                "UPDATE passkey_enrollment_capabilities "
                "SET claimed_flow_id=NULL, claimed_at=NULL "
                "WHERE claimed_flow_id=? AND consumed_at IS NULL AND revoked_at IS NULL",
                (flow_id,),
            ).rowcount
        return changed == 1

    def revoke(self, capability_id: str) -> bool:
        now = _now_utc(self._now)
        with self._connection(mutation=True) as connection:
            changed = connection.execute(
                "UPDATE passkey_enrollment_capabilities SET revoked_at=? "
                "WHERE capability_id=? AND consumed_at IS NULL AND revoked_at IS NULL",
                (now.isoformat(), capability_id),
            ).rowcount
        return changed == 1


def _optional_datetime(value: object) -> datetime | None:
    return datetime.fromisoformat(str(value)) if value is not None else None


def _capability_from_row(row: tuple[object, ...]) -> EnrollmentCapability:
    return EnrollmentCapability(
        capability_id=str(row[0]),
        purpose=cast(EnrollmentPurpose, str(row[1])),
        subject=str(row[2]),
        expires_at=datetime.fromisoformat(str(row[3])),
        issued_by=str(row[4]) if row[4] is not None else None,
        claimed_flow_id=str(row[5]) if row[5] is not None else None,
        claimed_at=_optional_datetime(row[6]),
        consumed_at=_optional_datetime(row[7]),
        revoked_at=_optional_datetime(row[8]),
    )
