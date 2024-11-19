from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

import oqs  # type: ignore[import-untyped]
from websockets import ConnectionClosed, ConnectionClosedError

from pqcow.client import Client
from pqcow.key_storage.key_storage import JSONKeyStorage

if TYPE_CHECKING:
    from key_storage.base import Key

logging.basicConfig(format="%(asctime)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)


class CloseReason(Enum):
    CLIENT_CLOSED = 0
    SERVER_CLOSED = 1
    TASK_CANCELLED = 2
    ERROR = 3


def create_dilithium_keypair() -> bytes:
    dilithium = oqs.Signature("Dilithium3")
    dilithium.generate_keypair()
    return dilithium.export_secret_key()


def recv_user_input() -> str:
    return input("Enter message to send: ")


async def sender(client: Client) -> CloseReason:
    try:
        while True:
            message = await asyncio.to_thread(recv_user_input)

            if message == "/exit":
                await client.close()
                return CloseReason.CLIENT_CLOSED

            try:
                await client.send_message(1, message)
                # await asyncio.gather(
                #     *[client.send_message(1, f"Message {i}") for i in range(10_000)]
                # )

            except ConnectionClosed:
                logger.info("Connection closed by the server")
                return CloseReason.SERVER_CLOSED

            # await asyncio.sleep(0.1)

    except asyncio.CancelledError:
        logger.info("Sender task was cancelled")
        return CloseReason.TASK_CANCELLED

    except Exception as e:
        logger.exception("An error occurred while sending message: %s", type(e).mro())
        return CloseReason.ERROR


async def start_client(host: str, port: int, identity: str) -> CloseReason:
    storage = JSONKeyStorage(Path("storage.enc"), "salt")

    with suppress(ValueError):
        storage.create_storage("password")

    storage.load_storage("password")

    try:
        key: Key = storage.get_key(identity)
    except KeyError:
        logger.info("Identity key for `%s` not found. Would you like to create one?", identity)
        create = input("[Y/n]: ")

        if create.casefold() != "y":
            return CloseReason.ERROR

        logger.info("Creating Identity key for `%s`...", identity)

        storage.set_key(identity, create_dilithium_keypair())
        storage.save_storage("password")

        logger.info("Identity key for `%s` created and saved", identity)

        key = storage.get_key(identity)

    client = Client(host, port, signature=oqs.Signature("Dilithium3", key.key))

    try:
        await client.connect()
    except ConnectionRefusedError:
        logger.info("Could not connect to server at %s:%s", host, port)
        return CloseReason.ERROR

    _task = asyncio.create_task(sender(client))

    try:
        async for answer in client:
            logger.info("Received answer: %s", answer)

    except ConnectionClosedError:
        logger.info("Connection closed by the server")
        _task.cancel()

    return await _task


if __name__ == "__main__":
    while True:
        close_reason = asyncio.run(start_client("127.0.0.1", 8080, identity="Ident"))

        match close_reason:
            case CloseReason.CLIENT_CLOSED | CloseReason.TASK_CANCELLED:
                break

            case CloseReason.SERVER_CLOSED:
                reconnect = input("Reconnect to server? [N/y]: ")

                if reconnect.lower() != "y":
                    break

            case CloseReason.ERROR:
                reconnect = input("Reconnect to server? [N/y]: ")

                if reconnect.lower() != "y":
                    break

    logger.info("Exiting client...")
