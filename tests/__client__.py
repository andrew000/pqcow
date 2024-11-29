from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

import oqs  # type: ignore[import-untyped]
from cryptography.fernet import InvalidToken
from websockets import ConnectionClosed, ConnectionClosedError

from pqcow.client import AsyncClient
from pqcow.key_storage.key_storage import JSONKeyStorage
from pqcow.pq_types.answer_types import Error
from pqcow.pq_types.answer_types.resolved_user import ResolvedUser

if TYPE_CHECKING:
    from pqcow.key_storage.base import Key

logging.basicConfig(format="%(asctime)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)


class CloseReason(Enum):
    CLIENT_CLOSED = 0
    SERVER_CLOSED = 1
    TASK_CANCELLED = 2
    ERROR = 3
    LOCAL_ERROR = 4


def create_dilithium_keypair() -> tuple[bytes, bytes]:
    dilithium = oqs.Signature("Dilithium3")
    public_key = dilithium.generate_keypair()
    return public_key, dilithium.export_secret_key()


def recv_user_input(text: str) -> str:
    return input(text)


async def sender(client: AsyncClient) -> CloseReason:
    try:
        while True:
            message = await asyncio.to_thread(recv_user_input, "Enter command: ")
            try:
                match message:
                    case "/exit":
                        await client.close()
                        return CloseReason.CLIENT_CLOSED

                    case "/resolve":
                        dilithium_public_key_hex = await asyncio.to_thread(
                            recv_user_input,
                            "Enter dilithium public key: ",
                        )
                        await client.resolve_user(bytes.fromhex(dilithium_public_key_hex))

                    case "/send":
                        user_id = int(await asyncio.to_thread(recv_user_input, "Enter user id: "))
                        message = await asyncio.to_thread(recv_user_input, "Enter message: ")
                        await client.send_message(user_id, message)

            except ConnectionClosed as e:
                logger.info("Connection closed by the server. Reason: %s", e.rcvd.reason)
                return CloseReason.SERVER_CLOSED

            await asyncio.sleep(0.1)

    except asyncio.CancelledError:
        logger.info("Sender task was cancelled")
        return CloseReason.TASK_CANCELLED

    except Exception as e:
        logger.exception("An error occurred while sending message: %s", e.args)
        return CloseReason.ERROR


async def start_client(
    host: str,
    port: int,
    name: str,
    storage_path: Path,
    storage_key: str | bytes,
) -> CloseReason:
    storage = JSONKeyStorage(storage_path)

    with suppress(ValueError):
        storage.create_storage(storage_key)

    try:
        storage.load_storage(storage_key)
    except InvalidToken:
        logger.exception("Invalid storage key")
        return CloseReason.LOCAL_ERROR

    try:
        key: Key = storage.get_key(name)
    except KeyError:
        logger.info("Identity key for `%s` not found. Would you like to create one?", name)
        create = input("[Y/n]: ")

        if create.casefold() != "y":
            return CloseReason.ERROR

        logger.info("Creating Identity key for `%s`...", name)

        public_key, private_key = create_dilithium_keypair()
        storage.set_key(name=name, public_key=public_key, private_key=private_key)
        storage.save_storage(storage_key)
        key = storage.get_key(name)

        logger.info("Identity key for `%s` created and saved", name)

    logger.info("Loaded Identity key for `%s`; %s", name, key.dilithium_public_key.hex())
    client = AsyncClient(
        host=host,
        port=port,
        signature=oqs.Signature("Dilithium3", key.dilithium_private_key),
        public_key=key.dilithium_public_key,
        username=name,
    )

    try:
        await client.connect()
    except ConnectionRefusedError:
        logger.info("Could not connect to server at %s:%s", host, port)
        return CloseReason.ERROR

    try:
        await client.register()
    except Exception as e:
        logger.exception("An error occurred while registering: %s", type(e).mro())
        return CloseReason.ERROR

    _task = asyncio.create_task(sender(client))

    try:
        async for answer, _event in client:
            if isinstance(answer, Error):
                logger.error("Received error: %s", answer)
                continue

            match answer.answer.data:
                case ResolvedUser() as resolved_user:
                    logger.info("Resolved user: ID: %s; %s", resolved_user.id, resolved_user)

                case _:
                    logger.info("Received answer: %s", answer)
                    continue

    except ConnectionClosedError as e:
        logger.info("Connection closed by the server. Reason: %s", e.rcvd.reason)

    finally:
        _task.cancel()

    return await _task


if __name__ == "__main__":
    while True:
        close_reason = asyncio.run(
            start_client(
                "127.0.0.1",
                8080,
                name="Andrew",
                storage_path=Path("storage.enc"),
                storage_key=input("Enter storage key: "),
            ),
        )

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

            case CloseReason.LOCAL_ERROR:
                break

    logger.info("Exiting client...")
