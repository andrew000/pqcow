from __future__ import annotations

from typing import Any, cast

from sqlalchemy import ScalarResult, and_, or_, select
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from pqcow.server.db.models.chats import ChatModel
from pqcow.server.db.models.messages import MessagesModel
from pqcow.server.db.models.users import UserModel
from pqcow.server.exceptions import UserAlreadyExistsError, UserNotFoundError


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
                .returning(UserModel)
            )
            user = await session.scalar(stmt)
            await session.commit()

            return cast(UserModel, user)

        raise UserAlreadyExistsError(username=username)

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
            stmt = select(ChatModel).filter(
                or_(
                    and_(ChatModel.user_id == initiator_id, ChatModel.chat_with_user_id == user.id),
                    and_(ChatModel.user_id == user.id, ChatModel.chat_with_user_id == initiator_id),
                ),
            )
            chat = await session.scalar(stmt)

            if not chat:
                stmt = (
                    insert(ChatModel)
                    .values(
                        user_id=initiator_id,
                        chat_with_user_id=user.id,
                    )
                    .on_conflict_do_nothing(index_elements=["user_id", "chat_with_user_id"])
                )
                await session.execute(stmt)
                await session.commit()

        return user

    @staticmethod
    async def chat_list(
        session: AsyncSession,
        user_id: int,
        limit: int = 100,
        offset: int = 0,
    ) -> ScalarResult[ChatModel]:
        stmt = (
            select(ChatModel)
            .filter(
                or_(ChatModel.user_id == user_id, ChatModel.chat_with_user_id == user_id),
            )
            .limit(limit)
            .offset(offset)
        )

        return await session.scalars(stmt)

    @staticmethod
    async def send_message(
        session: AsyncSession,
        sender_id: int,
        receiver_id: int,
        text: str,
        signature: bytes,
    ) -> MessagesModel:
        # Check if chat exists
        stmt = select(ChatModel).filter(
            or_(
                and_(ChatModel.user_id == sender_id, ChatModel.chat_with_user_id == receiver_id),
                and_(ChatModel.user_id == receiver_id, ChatModel.chat_with_user_id == sender_id),
            ),
        )
        chat = await session.scalar(stmt)

        if not chat:
            raise UserNotFoundError(user_id=receiver_id)

        # Insert message
        stmt = (
            insert(MessagesModel)
            .values(
                chat_id=chat.id,
                sender_id=sender_id,
                receiver_id=receiver_id,
                message=text,
                signature=signature,
            )
            .returning(MessagesModel)
        )
        message = await session.scalar(stmt)
        await session.commit()

        return cast(MessagesModel, message)

    @staticmethod
    async def poll_messages(
        session: AsyncSession,
        user_id: int,
        chat_id: int,
        last_message_id: int,
    ) -> ScalarResult[MessagesModel]:
        stmt = (
            select(MessagesModel)
            .filter(
                MessagesModel.chat_id == chat_id,
                or_(MessagesModel.sender_id == user_id, MessagesModel.receiver_id == user_id),
            )
            .order_by(MessagesModel.message_id)
            .limit(100)
        )

        if last_message_id:
            stmt = stmt.filter(MessagesModel.message_id > last_message_id)

        return await session.scalars(stmt)
