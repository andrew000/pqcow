from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import msgspec.msgpack
import oqs  # type: ignore[import-untyped]

from pqcow.server import Server
from pqcow.server.db.base import create_sqlite_session_pool
from pqcow.server.db.db import ServerDatabase

logging.basicConfig(format="%(asctime)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)


async def start_server(host: str, port: int) -> None:
    dilithium_path = Path("dilithium.key")

    if not dilithium_path.exists():
        dilithium = oqs.Signature("Dilithium3")
        public_key = dilithium.generate_keypair()
        private_key = dilithium.export_secret_key()

        dilithium_path.write_bytes(
            msgspec.msgpack.encode(
                {"public_key": public_key, "private_key": private_key},
            ),
        )

    loaded_dilithium: dict[str, bytes] = msgspec.msgpack.decode(dilithium_path.read_bytes())

    server = Server(
        host=host,
        port=port,
        signature=oqs.Signature("Dilithium3", secret_key=loaded_dilithium["private_key"]),
        dilithium_public_key=loaded_dilithium["public_key"],
        db=ServerDatabase(*(await create_sqlite_session_pool())),
    )

    await server.start()


if __name__ == "__main__":
    asyncio.run(start_server("127.0.0.1", 8080))
