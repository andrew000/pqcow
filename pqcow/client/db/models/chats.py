from datetime import datetime

from sqlalchemy import TIMESTAMP, BigInteger, ForeignKey, Index, Integer
from sqlalchemy.orm import Mapped, mapped_column

from pqcow.client.db.base import Base


class KnownChatModel(Base):
    __tablename__ = "known_chats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("known_users.id", ondelete="RESTRICT", onupdate="RESTRICT"),
        nullable=False,
    )
    chat_with_user_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("known_users.id", ondelete="RESTRICT", onupdate="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=False), nullable=False)

    __table_args__ = (
        Index(None, "user_id"),
        Index("ix_chats_user_id__chat_with_user_id", "user_id", "chat_with_user_id", unique=True),
    )
