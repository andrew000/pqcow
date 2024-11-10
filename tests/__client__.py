from __future__ import annotations

import asyncio
import logging
from enum import Enum
from pathlib import Path

import oqs  # type: ignore[import-untyped]
from websockets import ConnectionClosed, ConnectionClosedError

from pqcow_client import Client

logging.basicConfig(format="%(asctime)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)


class CloseReason(Enum):
    CLIENT_CLOSED = 0
    SERVER_CLOSED = 1
    TASK_CANCELLED = 2
    ERROR = 3


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

            except ConnectionClosed:
                logger.info("Connection closed by the server")
                return CloseReason.SERVER_CLOSED

            await asyncio.sleep(0.1)

    except asyncio.CancelledError:
        logger.info("Sender task was cancelled")
        return CloseReason.TASK_CANCELLED

    except Exception as e:
        logger.exception("An error occurred while sending message: %s", type(e).mro())
        return CloseReason.ERROR


async def start_client(host: str, port: int) -> CloseReason:
    dilithium_path = Path("dilithium.key")

    if not dilithium_path.exists():
        dilithium = oqs.Signature("Dilithium3")
        dilithium.generate_keypair()
        private_key = dilithium.export_secret_key()

        dilithium_path.write_bytes(private_key)

    dilithium = oqs.Signature("Dilithium3", secret_key=dilithium_path.read_bytes())

    # try:
    #     reader, writer = await asyncio.open_connection(host, port)
    # except ConnectionRefusedError:
    #     logger.info("Could not connect to server at %s:%s", host, port)
    #     return
    # except Exception as e:
    #     logger.exception("An error occurred while connecting to server: %s", type(e).mro())
    #     return
    #
    # logger.info("Connected to server at %s:%s", host, port)
    #
    # shared_secret = await key_exchange(reader, writer)
    # salt = await reader.read(16)
    # hkdf = create_hkdf(salt)
    # key = hkdf.derive(shared_secret)
    #
    # while True:
    #     # await asyncio.sleep(0.1)
    #     # message = input("Enter message to send: ")
    #     message = "Hello from client"
    #
    #     if message == "/exit":
    #         break
    #
    #     try:
    #         request = Request(request=Message(text=message))
    #         await send_request(writer, key, request)
    #
    #         answer = await receive_answer(reader, key)
    #
    #     except struct.error:
    #         logger.info("Error receiving answer")
    #         return
    #
    #     except (ConnectionResetError, ConnectionAbortedError):
    #         logger.info("Server closed connection")
    #         return
    #
    #     logger.info("Received answer: %s", answer)

    client = Client(host, port, dilithium)

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
        close_reason = asyncio.run(start_client("127.0.0.1", 8080))

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
