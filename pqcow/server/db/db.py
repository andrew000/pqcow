from collections.abc import Iterable
from pathlib import Path
from sqlite3 import Row
from typing import Any, cast

import aiosqlite
from aiosqlite import Cursor


def dict_factory(cursor: Cursor, row: Row) -> dict[str, str]:
    fields = [column[0] for column in cursor.description]
    return dict(zip(fields, row, strict=False))


class ServerDatabase:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._connection: aiosqlite.Connection | None = None

    async def create_connection(self) -> None:
        if self._connection:
            msg = "Connection already exists"
            raise RuntimeError(msg)

        self._connection = await aiosqlite.connect(self.db_path)
        self._connection.row_factory = cast(type[Any], dict_factory)

    @property
    def connection(self) -> aiosqlite.Connection:
        if not self._connection:
            msg = "Connection does not exist"
            raise RuntimeError(msg)

        return self._connection

    @connection.getter
    def connection(self) -> aiosqlite.Connection:
        if not self._connection:
            msg = "Connection does not exist"
            raise RuntimeError(msg)

        return self._connection

    async def resolve_user_by_dilithium(
        self,
        dilithium_public_key: bytes,
    ) -> tuple[int, str] | None:
        async with self.connection.execute(
            "SELECT id, username FROM users WHERE dilithium_public_key = ?",
            (dilithium_public_key,),
        ) as cursor:
            row: Row | None = await cursor.fetchone()

        return (row["id"], row["username"]) if row else None

    async def register_user(self, username: str, dilithium_public_key: bytes) -> int:
        async with self.connection.execute(
            "INSERT INTO users (username, dilithium_public_key) "
            "VALUES (?, ?) "
            "ON CONFLICT DO NOTHING "
            "RETURNING id",
            (username, dilithium_public_key),
        ) as cursor:
            user_id = cast(dict[str, Any], await cursor.fetchone())
            await self.connection.commit()
            return user_id["id"]

    async def chat_list_main(self, user_id: int) -> Iterable[Row]:
        async with self.connection.execute(
            "SELECT id, user_id, chat_with_user_id, created_at FROM chats WHERE user_id = ?",
            (user_id,),
        ) as cursor:
            return await cursor.fetchall()
