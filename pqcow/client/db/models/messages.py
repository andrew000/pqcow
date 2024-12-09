from datetime import datetime

from sqlalchemy import BLOB, TIMESTAMP, BigInteger, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from pqcow.client.db.base import Base


class MessagesModel(Base):
    __tablename__ = "messages"

    message_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    chat_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("known_chats.id"),
        nullable=False,
    )
    sender_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("known_users.id"), nullable=False)
    receiver_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("known_users.id"),
        nullable=False,
    )
    message: Mapped[str] = mapped_column(String, nullable=False)
    signature: Mapped[bytes] = mapped_column(BLOB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP, nullable=False)

    __table_args__ = (Index(None, "chat_id"), Index(None, "sender_id"))

    def __repr__(self) -> str:
        values = ", ".join(
            [
                f"{column.name}={getattr(self, column.name)}"
                for column in self.__table__.columns.values()
                if column.name != "signature"
            ],
        )
        return f"{self.__tablename__}({values})"
