from datetime import UTC, datetime
from functools import partial

from sqlalchemy import BLOB, TIMESTAMP, BigInteger, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from pqcow.server.db.base import Base


class MessagesModel(Base):
    __tablename__ = "messages"

    message_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    chat_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("chats.id"),
        nullable=False,
    )
    sender_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    receiver_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    message: Mapped[str] = mapped_column(String, nullable=False)
    signature: Mapped[bytes] = mapped_column(BLOB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP,
        nullable=False,
        default=partial(datetime.now, tz=UTC),
    )

    __table_args__ = (Index(None, "sender_id"), {"sqlite_autoincrement": True})
