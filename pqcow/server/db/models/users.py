from datetime import UTC, datetime
from functools import partial

from sqlalchemy import BLOB, TIMESTAMP, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from pqcow.server.db.base import Base


class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(collation="NOCASE"), nullable=False, unique=True)
    dilithium_public_key: Mapped[bytes] = mapped_column(BLOB, nullable=False, unique=True)
    registration_datetime: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=False),
        nullable=False,
        default=partial(datetime.now, tz=UTC),
    )

    __table_args__ = (
        Index(None, "dilithium_public_key", unique=True),
        {"sqlite_autoincrement": True},
    )
