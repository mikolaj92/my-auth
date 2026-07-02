from __future__ import annotations

from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    select,
    update,
)
from sqlalchemy.engine import Engine

from .passkeys import CredentialNotFound, PasskeyCredential, PasskeyUser
from .stores import (
    backed_up_from_int,
    created_at_from_iso,
    created_at_to_iso,
    transports_from_json,
    transports_to_json,
)


def build_tables(metadata: MetaData) -> tuple[Table, Table]:
    users = Table(
        "passkey_users",
        metadata,
        Column("user_id", String, primary_key=True),
        Column("user_handle", LargeBinary, nullable=False, unique=True),
        Column("name", String, nullable=False),
        Column("display_name", String, nullable=True),
    )
    credentials = Table(
        "passkey_credentials",
        metadata,
        Column("credential_id", LargeBinary, primary_key=True),
        Column("user_id", String, ForeignKey("passkey_users.user_id"), nullable=False),
        Column("public_key", LargeBinary, nullable=False),
        Column("sign_count", Integer, nullable=False, default=0),
        Column("transports", Text, nullable=False, default="[]"),
        Column("device_type", String, nullable=True),
        Column("backed_up", Boolean, nullable=True),
        Column("label", String, nullable=True),
        Column("created_at", String, nullable=False),
        Index("ix_passkey_credentials_user_id", "user_id"),
    )
    return users, credentials


class SQLAlchemyCredentialStore:
    """CredentialStore backed by a SQLAlchemy Core engine using the standard passkey schema."""

    def __init__(self, engine: Engine, *, metadata: MetaData | None = None) -> None:
        self.engine = engine
        self.metadata = metadata or MetaData()
        self.users, self.credentials = build_tables(self.metadata)

    def create_tables(self) -> None:
        self.metadata.create_all(self.engine, tables=[self.users, self.credentials])

    def _credential_values(self, credential: PasskeyCredential) -> dict[str, Any]:
        return {
            "credential_id": credential.credential_id,
            "user_id": credential.user_id,
            "public_key": credential.public_key,
            "sign_count": credential.sign_count,
            "transports": transports_to_json(credential.transports),
            "device_type": credential.device_type,
            "backed_up": credential.backed_up,
            "label": credential.label,
            "created_at": created_at_to_iso(credential.created_at),
        }

    @staticmethod
    def _user_from_row(row: Any) -> PasskeyUser:
        return PasskeyUser(
            user_id=row.user_id,
            user_handle=bytes(row.user_handle),
            name=row.name,
            display_name=row.display_name,
        )

    @staticmethod
    def _credential_from_row(row: Any) -> PasskeyCredential:
        backed_up = row.backed_up
        return PasskeyCredential(
            credential_id=bytes(row.credential_id),
            user_id=row.user_id,
            public_key=bytes(row.public_key),
            sign_count=row.sign_count,
            transports=transports_from_json(row.transports),
            device_type=row.device_type,
            backed_up=backed_up_from_int(int(backed_up) if backed_up is not None else None),
            label=row.label,
            created_at=created_at_from_iso(row.created_at),
        )

    def save_user(self, user: PasskeyUser) -> None:
        values = {
            "user_id": user.user_id,
            "user_handle": user.user_handle,
            "name": user.name,
            "display_name": user.display_name,
        }
        with self.engine.begin() as connection:
            updated = connection.execute(
                update(self.users).where(self.users.c.user_id == user.user_id).values(**values)
            )
            if updated.rowcount == 0:
                connection.execute(self.users.insert().values(**values))

    def get_user(self, user_id: str) -> PasskeyUser | None:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(self.users).where(self.users.c.user_id == user_id)
            ).first()
        return self._user_from_row(row) if row else None

    def get_user_by_handle(self, user_handle: bytes) -> PasskeyUser | None:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(self.users).where(self.users.c.user_handle == user_handle)
            ).first()
        return self._user_from_row(row) if row else None

    def list_credentials_for_user(self, user_id: str) -> list[PasskeyCredential]:
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(self.credentials)
                .where(self.credentials.c.user_id == user_id)
                .order_by(self.credentials.c.created_at)
            ).all()
        return [self._credential_from_row(row) for row in rows]

    def get_credential(self, credential_id: bytes) -> PasskeyCredential | None:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(self.credentials).where(self.credentials.c.credential_id == credential_id)
            ).first()
        return self._credential_from_row(row) if row else None

    def save_credential(self, credential: PasskeyCredential) -> None:
        values = self._credential_values(credential)
        with self.engine.begin() as connection:
            updated = connection.execute(
                update(self.credentials)
                .where(self.credentials.c.credential_id == credential.credential_id)
                .values(**{key: value for key, value in values.items() if key != "created_at"})
            )
            if updated.rowcount == 0:
                connection.execute(self.credentials.insert().values(**values))

    def update_credential_after_login(
        self,
        credential_id: bytes,
        *,
        sign_count: int,
        device_type: str | None,
        backed_up: bool | None,
    ) -> PasskeyCredential:
        with self.engine.begin() as connection:
            result = connection.execute(
                update(self.credentials)
                .where(self.credentials.c.credential_id == credential_id)
                .values(sign_count=sign_count, device_type=device_type, backed_up=backed_up)
            )
            if result.rowcount == 0:
                raise CredentialNotFound("unknown passkey credential")
        credential = self.get_credential(credential_id)
        assert credential is not None
        return credential
