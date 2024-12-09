from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, cast

from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from pqcow.client.db.models import IdentityModel
from pqcow.client.db.models.chats import KnownChatModel
from pqcow.client.db.models.known_users import KnownUserModel
from pqcow.client.db.models.messages import MessagesModel

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.orm import DeclarativeBase

    from pqcow.pq_types.answer_types.chat_list_answer import ChatListAnswer
    from pqcow.pq_types.answer_types.message import Message


class ClientDatabase[T: async_sessionmaker[AsyncSession]]:
    def __init__(self, engine: AsyncEngine, sessionmaker: T) -> None:
        self._engine = engine
        self._sessionmaker = sessionmaker
        self._is_initialized = False
        self._is_closed = False

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    @property
    def sessionmaker(self) -> T:
        return self._sessionmaker

    @property
    def is_initialized(self) -> bool:
        return self._is_initialized

    @is_initialized.setter
    def is_initialized(self, _: bool) -> None:
        msg = "Cannot set is_initialized attribute."
        raise AttributeError(msg)

    @property
    def is_closed(self) -> bool:
        return self._is_closed

    @is_closed.setter
    def is_closed(self, _: bool) -> None:
        msg = "Cannot set is_closed attribute."
        raise AttributeError(msg)

    async def init_db(self, base_model: type[DeclarativeBase]) -> None:
        if self._is_initialized:
            return

        async with self.engine.begin() as conn:
            # stmt = text("CREATE EXTENSION IF NOT EXISTS citext;")  # For PostgreSQL
            # await conn.execute(stmt)

            await conn.run_sync(base_model.metadata.create_all)

        self._is_initialized = True

    async def close(self) -> None:
        self._is_closed = True
        await self._engine.dispose()

    @staticmethod
    async def new_user(
        session: AsyncSession,
        user_id: int,
        username: str,
        dilithium_public_key: bytes,
    ) -> KnownUserModel:
        stmt = (
            insert(KnownUserModel)
            .values(
                id=user_id,
                username=username,
                dilithium_public_key=dilithium_public_key,
            )
            .on_conflict_do_nothing(index_elements=["id"])
            .returning(KnownUserModel)
        )
        user = await session.scalar(stmt)
        await session.commit()

        return cast(KnownUserModel, user)

    @staticmethod
    async def get_user_by_id(
        session: AsyncSession,
        user_id: int,
    ) -> KnownUserModel | None:
        """Get user by id."""
        stmt: Any = select(KnownUserModel).filter(KnownUserModel.id == user_id)
        return await session.scalar(stmt)

    @staticmethod
    async def get_user_by_dilithium(
        session: AsyncSession,
        dilithium_public_key: bytes,
    ) -> KnownUserModel | None:
        """Get user by dilithium public key."""
        stmt: Any = select(KnownUserModel).filter(
            KnownUserModel.dilithium_public_key == dilithium_public_key,
        )
        return await session.scalar(stmt)

    @staticmethod
    async def new_chat(
        session: AsyncSession,
        user_id: int,
        chat_with_user_id: int,
        created_at: datetime,
    ) -> KnownChatModel:
        stmt = (
            insert(KnownChatModel)
            .values(
                user_id=user_id,
                chat_with_user_id=chat_with_user_id,
                created_at=created_at,
            )
            .on_conflict_do_nothing(index_elements=["user_id", "chat_with_user_id"])
            .returning(KnownChatModel)
        )
        chat = await session.scalar(stmt)
        await session.commit()

        return cast(KnownChatModel, chat)

    @staticmethod
    async def batch_insert_chats(
        session: AsyncSession,
        chat_list: ChatListAnswer,
    ) -> None:
        for chat in chat_list.chats:
            stmt = (
                insert(KnownChatModel)
                .values(
                    id=chat.id,
                    user_id=chat.user_id,
                    chat_with_user_id=chat.chat_with_user_id,
                    created_at=chat.created_at,
                )
                .on_conflict_do_nothing(index_elements=["user_id", "chat_with_user_id"])
            )
            await session.execute(stmt)

        await session.commit()

    @staticmethod
    async def get_chat_by_id(
        session: AsyncSession,
        chat_id: int,
    ) -> KnownChatModel | None:
        """Get chat by id."""
        stmt: Any = select(KnownChatModel).filter(KnownChatModel.id == chat_id)
        return await session.scalar(stmt)

    @staticmethod
    async def get_chat_ids(session: AsyncSession) -> list[int]:
        stmt = select(KnownChatModel.id)
        return list(await session.scalars(stmt))

    @staticmethod
    async def new_message_in_chat(
        session: AsyncSession,
        message_id: int,
        chat_id: int,
        sender_id: int,
        receiver_id: int,
        message: str,
        signature: bytes,
        created_at: datetime,
    ) -> None:
        stmt = (
            insert(MessagesModel)
            .values(
                message_id=message_id,
                chat_id=chat_id,
                sender_id=sender_id,
                receiver_id=receiver_id,
                message=message,
                signature=signature,
                created_at=created_at,
            )
            .returning(MessagesModel)
        )
        await session.execute(stmt)
        await session.commit()

    @staticmethod
    async def batch_insert_messages(
        session: AsyncSession,
        messages: list[Message],
    ) -> None:
        for message in messages:
            stmt = (
                insert(MessagesModel)
                .values(
                    message_id=message.message_id,
                    chat_id=message.chat_id,
                    sender_id=message.sender_id,
                    receiver_id=message.receiver_id,
                    message=message.text,
                    signature=message.sign,
                    created_at=message.created_at,
                )
                .on_conflict_do_nothing(index_elements=["message_id"])
            )

            await session.execute(stmt)

        await session.commit()

    @staticmethod
    async def get_messages_by_chat_id(
        session: AsyncSession,
        chat_id: int,
        last_message_id: int = 0,
        limit: int = 100,
    ) -> list[MessagesModel]:
        stmt = (
            select(MessagesModel)
            .filter(MessagesModel.chat_id == chat_id)
            .order_by(MessagesModel.message_id.desc())
            .limit(limit)
        )

        if last_message_id:
            stmt = stmt.filter(MessagesModel.message_id > last_message_id)

        return list(await session.scalars(stmt))

    async def new_identity(
        self,
        username: str,
        type_: Literal["client", "server"],
        public_key: bytes,
        private_key: bytes | None = None,
    ) -> IdentityModel:
        async with self.sessionmaker() as session:
            stmt = (
                insert(IdentityModel)
                .values(
                    username=username,
                    type=type_,
                    dilithium_public_key=public_key,
                    dilithium_private_key=private_key,
                )
                .returning(IdentityModel)
            )
            identity = await session.scalar(stmt)
            await session.commit()

            return cast(IdentityModel, identity)

    async def get_identity(
        self,
        identity_name: str,
        type_: Literal["client", "server"],
    ) -> IdentityModel | None:
        async with self.sessionmaker() as session:
            stmt = select(IdentityModel).where(
                IdentityModel.username == identity_name,
                IdentityModel.type == type_,
            )
            return await session.scalar(stmt)
