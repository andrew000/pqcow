from sqlalchemy import BLOB, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from pqcow.client.db.base import Base


class KnownUserModel(Base):
    __tablename__ = "known_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(collation="NOCASE"), nullable=False, unique=True)
    dilithium_public_key: Mapped[bytes] = mapped_column(BLOB, nullable=False, unique=True)

    __table_args__ = (
        Index(None, "id", unique=True),
        Index(None, "username", unique=True),
        Index(None, "dilithium_public_key", unique=True),
    )
