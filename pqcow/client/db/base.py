from typing import Final

from sqlalchemy import URL
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

DATABASE_NAME: Final[str] = "pqcow-client.db"


class Base(DeclarativeBase):
    def __repr__(self) -> str:
        values = ", ".join(
            [
                f"{column.name}={getattr(self, column.name)}"
                for column in self.__table__.columns.values()
            ],
        )
        return f"{self.__tablename__}({values})"


async def create_sqlite_session_pool() -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    engine: AsyncEngine = create_async_engine(
        url=URL.create(
            drivername="sqlite+aiosqlite",
            database=DATABASE_NAME,
        ),
    )

    return engine, async_sessionmaker(engine, expire_on_commit=False)


async def init_db(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        # stmt = text("CREATE EXTENSION IF NOT EXISTS citext;")  # For PostgreSQL
        # await conn.execute(stmt)

        await conn.run_sync(Base.metadata.create_all)
