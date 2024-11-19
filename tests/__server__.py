from __future__ import annotations

import asyncio
import logging
import signal
from pathlib import Path

import oqs  # type: ignore[import-untyped]

from pqcow.server import Server

logging.basicConfig(format="%(asctime)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)


async def start_server(host: str, port: int) -> None:
    dilithium_path = Path("dilithium.key")

    if not dilithium_path.exists():
        dilithium = oqs.Signature("Dilithium3")
        dilithium.generate_keypair()
        private_key = dilithium.export_secret_key()

        dilithium_path.write_bytes(private_key)

    dilithium = oqs.Signature("Dilithium3", secret_key=dilithium_path.read_bytes())

    server = Server(host, port, dilithium)
    signal.signal(signal.SIGINT, server.signal_handler)
    # signal.signal(signal.SIGTERM, self._signal_handler)
    await server.start()


if __name__ == "__main__":
    asyncio.run(start_server("127.0.0.1", 8080))
