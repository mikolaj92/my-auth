from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .passkeys import ChallengeKind, ChallengeNotFound, ChallengeRecord, PasskeyUser, b64url_to_bytes, bytes_to_b64url


class SQLiteChallengeStore:
    def __init__(self, path: str | Path, *, now: Callable[[], datetime] | None = None) -> None:
        self.path = Path(path)
        self._now = now or (lambda: datetime.now(UTC))
        if self.path.parent != Path(""):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def save(
        self,
        *,
        key: str,
        kind: ChallengeKind,
        challenge: bytes,
        ttl_seconds: int,
        user: PasskeyUser | None = None,
    ) -> ChallengeRecord:
        expires_at = self._now() + timedelta(seconds=ttl_seconds)
        record = ChallengeRecord(challenge=challenge, kind=kind, key=key, expires_at=expires_at, user=user)
        user_handle = bytes_to_b64url(user.user_handle) if user is not None else None
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO passkey_challenges (
                    flow_key,
                    kind,
                    challenge,
                    expires_at,
                    user_id,
                    user_handle,
                    user_name,
                    user_display_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    key,
                    kind,
                    bytes_to_b64url(challenge),
                    expires_at.isoformat(),
                    user.user_id if user is not None else None,
                    user_handle,
                    user.name if user is not None else None,
                    user.display_name if user is not None else None,
                ),
            )
        return record

    def pop(self, *, key: str, kind: ChallengeKind) -> ChallengeRecord:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT challenge, expires_at, user_id, user_handle, user_name, user_display_name
                FROM passkey_challenges
                WHERE flow_key = ? AND kind = ?
                """,
                (key, kind),
            ).fetchone()
            if row is None:
                raise ChallengeNotFound(f"missing or expired {kind} challenge")

            connection.execute(
                "DELETE FROM passkey_challenges WHERE flow_key = ? AND kind = ?",
                (key, kind),
            )

        record = self._record_from_row(key=key, kind=kind, row=row)
        if record.expires_at <= self._now():
            raise ChallengeNotFound(f"missing or expired {kind} challenge")
        return record

    def delete_expired(self) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM passkey_challenges WHERE expires_at <= ?",
                (self._now().isoformat(),),
            )
        return cursor.rowcount if cursor.rowcount >= 0 else 0

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS passkey_challenges (
                    flow_key TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    challenge TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    user_id TEXT,
                    user_handle TEXT,
                    user_name TEXT,
                    user_display_name TEXT,
                    PRIMARY KEY (flow_key, kind)
                )
                """
            )

    @staticmethod
    def _record_from_row(*, key: str, kind: ChallengeKind, row: tuple[str, str, str | None, str | None, str | None, str | None]) -> ChallengeRecord:
        challenge, expires_at, user_id, user_handle, user_name, user_display_name = row
        user = None
        if user_id is not None and user_handle is not None and user_name is not None:
            user = PasskeyUser(
                user_id=user_id,
                user_handle=b64url_to_bytes(user_handle),
                name=user_name,
                display_name=user_display_name,
            )
        return ChallengeRecord(
            challenge=b64url_to_bytes(challenge),
            kind=kind,
            key=key,
            expires_at=datetime.fromisoformat(expires_at),
            user=user,
        )
