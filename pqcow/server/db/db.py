from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from pqcow.server.db.models.chats import ChatModel
from pqcow.server.db.models.messages import MessagesModel
from pqcow.server.db.models.users import UserModel
from pqcow.server.exceptions import ChatNotFoundError

if TYPE_CHECKING:
    from collections.abc import Iterable
    from sqlite3 import Row


class ServerDatabase[T: async_sessionmaker[AsyncSession]]:
    def __init__(self, engine: AsyncEngine, sessionmaker: T) -> None:
        self._engine = engine
        self._sessionmaker = sessionmaker
        self.is_closed = False

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    @property
    def sessionmaker(self) -> T:
        return self._sessionmaker

    async def close(self) -> None:
        self.is_closed = True
        await self._engine.dispose()

    @staticmethod
    async def register_user(
        session: AsyncSession,
        username: str,
        dilithium_public_key: bytes,
    ) -> UserModel:
        stmt: Any = select(UserModel).filter(UserModel.username == username)
        user = await session.scalar(stmt)

        if not user:
            stmt = (
                insert(UserModel)
                .values(
                    username=username,
                    dilithium_public_key=dilithium_public_key,
                )
                # .on_conflict_do_nothing(index_elements=["dilithium_public_key"])
                .returning(UserModel)
            )
            user = await session.scalar(stmt)
            await session.commit()

        return cast(UserModel, user)

    @staticmethod
    async def resolve_user_by_dilithium(
        session: AsyncSession,
        initiator_id: int | None,
        dilithium_public_key: bytes,
    ) -> UserModel | None:
        """
        Resolve user by dilithium public key.

        This also creates a chat with the user if it does not exist.
        """
        stmt: Any = select(UserModel).filter(UserModel.dilithium_public_key == dilithium_public_key)
        user = await session.scalar(stmt)

        if initiator_id is not None and user:
            stmt = (
                insert(ChatModel)
                .values(
                    user_id=initiator_id,
                    chat_with_user_id=user.id,
                )
                .on_conflict_do_nothing(index_elements=["user_id", "chat_with_user_id"])
            )
            await session.execute(stmt)

            stmt = (
                insert(ChatModel)
                .values(
                    user_id=user.id,
                    chat_with_user_id=initiator_id,
                )
                .on_conflict_do_nothing(index_elements=["user_id", "chat_with_user_id"])
            )
            await session.execute(stmt)

            await session.commit()

        return user

    @staticmethod
    async def chat_list_main(
        session: AsyncSession,
        user_id: int,
        limit: int = 100,
        offset: int = 0,
    ) -> Iterable[Row]: ...

    @staticmethod
    async def send_message(
        session: AsyncSession,
        chat_id: int,
        sender_id: int,
        receiver_id: int,
        text: str,
        signature: bytes,
    ) -> MessagesModel:
        # Select chat
        stmt = select(ChatModel).filter(
            ChatModel.user_id == sender_id,
            ChatModel.chat_with_user_id == receiver_id,
        )
        chat = await session.scalar(stmt)

        if not chat:
            raise ChatNotFoundError(chat_id=chat_id)

        # Insert message
        stmt = (
            insert(MessagesModel)
            .values(
                chat_id=chat_id,
                sender_id=sender_id,
                message=text,
                signature=signature,
            )
            .returning(MessagesModel)
        )
        message = await session.scalar(stmt)
        await session.commit()

        return cast(MessagesModel, message)
