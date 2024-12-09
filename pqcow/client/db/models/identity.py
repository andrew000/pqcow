from sqlalchemy import BLOB, CheckConstraint, Index, PrimaryKeyConstraint, String
from sqlalchemy.orm import Mapped, mapped_column

from pqcow.client.db.base import Base


class IdentityModel(Base):
    """Identity model to store client and server identities."""

    __tablename__ = "identities"

    username: Mapped[str] = mapped_column(String(collation="NOCASE"), nullable=False)
    type: Mapped[str] = mapped_column(String, nullable=False)
    dilithium_public_key: Mapped[bytes] = mapped_column(BLOB, nullable=False, unique=True)
    dilithium_private_key: Mapped[bytes] = mapped_column(BLOB, nullable=True)

    __table_args__ = (
        PrimaryKeyConstraint("username", "type"),
        Index(None, "dilithium_public_key", unique=True),
        CheckConstraint("type IN ('client', 'server')"),
        # If type is server, dilithium_private_key should be NULL.
        CheckConstraint(
            "(type = 'server' AND dilithium_private_key IS NULL) OR "
            "(type = 'client' AND dilithium_private_key IS NOT NULL)",
        ),
    )
