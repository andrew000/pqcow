from __future__ import annotations

import asyncio
import logging
import struct
from pathlib import Path

import oqs  # type: ignore[import-untyped]

from pqcow_client.src.keys import create_hkdf, key_exchange
from pqcow_func.src.message import receive_answer, send_request
from pqcow_types.src.message import Message
from pqcow_types.src.request import Request

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def start_client(host: str, port: int) -> None:
    dilithium_path = Path("dilithium.key")

    if not dilithium_path.exists():
        dilithium = oqs.Signature("Dilithium3")
        dilithium.generate_keypair()
        private_key = dilithium.export_secret_key()

        dilithium_path.write_bytes(private_key)

    dilithium = oqs.Signature("Dilithium3", secret_key=dilithium_path.read_bytes())

    try:
        reader, writer = await asyncio.open_connection(host, port)
    except ConnectionRefusedError:
        logger.info("Could not connect to server at %s:%s", host, port)
        return
    except Exception as e:
        logger.exception("An error occurred while connecting to server: %s", type(e).mro())
        return

    logger.info("Connected to server at %s:%s", host, port)

    shared_secret = await key_exchange(reader, writer)
    salt = await reader.read(16)
    hkdf = create_hkdf(salt)
    key = hkdf.derive(shared_secret)

    while True:
        # await asyncio.sleep(0.1)
        # message = input("Enter message to send: ")
        message = "Hello from client"

        if message == "/exit":
            break

        try:
            request = Request(request=Message(text=message))
            await send_request(writer, key, request)

            answer = await receive_answer(reader, key)

        except struct.error:
            logger.info("Error receiving answer")
            return

        except (ConnectionResetError, ConnectionAbortedError):
            logger.info("Server closed connection")
            return

        logger.info("Received answer: %s", answer)


if __name__ == "__main__":
    while True:
        asyncio.run(start_client("127.0.0.1", 8080))
        reconnect = input("Reconnect to server? [N/y]: ")

        if reconnect.lower() != "y":
            break
