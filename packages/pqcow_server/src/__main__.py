from __future__ import annotations

import asyncio
import logging
from functools import partial
from pathlib import Path

import msgspec.msgpack
import oqs  # type: ignore[import-untyped]

from pqcow_func.src.message import receive_request, send_answer
from pqcow_server.src.keys import create_hkdf, key_exchange
from pqcow_types.src.answer import Answer
from pqcow_types.src.error import Error
from pqcow_types.src.message import Message

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, _dilithium: oqs.Signature) -> None:
    logger.info("[%s] New connection from %s", writer.get_extra_info("peername"), writer.get_extra_info("peername"))

    try:
        shared_secret = await key_exchange(reader, writer)

    except msgspec.DecodeError:
        logger.info("[%s] Error decoding message while key exchange", writer.get_extra_info("peername"))
        return

    except ConnectionResetError:
        logger.info("[%s] Connection closed by the client while key exchange", writer.get_extra_info("peername"))
        return

    except Exception as e:
        logger.exception(
            "[%s] An error occurred while key exchange: %s",
            writer.get_extra_info("peername"),
            type(e).mro(),
        )
        return

    hkdf, salt = create_hkdf()
    key = hkdf.derive(shared_secret)
    writer.write(salt)
    await writer.drain()

    while True:
        try:
            request = await asyncio.wait_for(receive_request(reader, key), timeout=60.0)

            if isinstance(request.request, Message):
                logger.info(
                    "[%s] Received request: request=%s",
                    writer.get_extra_info("peername"),
                    request,
                )

            await send_answer(writer, key, Answer(answer=Message(text="Message received")))

        except asyncio.IncompleteReadError:
            logger.info(
                "[%s] Connection closed by the client %s",
                writer.get_extra_info("peername"),
                writer.get_extra_info("peername"),
            )
            break

        except msgspec.DecodeError:
            logger.info("[%s] Error decoding message", writer.get_extra_info("peername"))
            raise

        except ConnectionResetError:
            logger.info("[%s] Connection closed by the client", writer.get_extra_info("peername"))
            break

        except TimeoutError:
            try:
                await send_answer(writer, key, Answer(answer=Error(code=1, message="Timeout occurred")))

            except ConnectionResetError:
                logger.info("[%s] Connection closed by the client", writer.get_extra_info("peername"))

            logger.info("[%s] Timeout occurred", writer.get_extra_info("peername"))
            break

        except Exception as e:
            logger.exception("[%s] An error occurred: %s", writer.get_extra_info("peername"), type(e).mro())
            break


async def start_server(host: str, port: int) -> None:
    dilithium_path = Path("dilithium.key")

    if not dilithium_path.exists():
        dilithium = oqs.Signature("Dilithium3")
        dilithium.generate_keypair()
        private_key = dilithium.export_secret_key()

        dilithium_path.write_bytes(private_key)

    dilithium = oqs.Signature("Dilithium3", secret_key=dilithium_path.read_bytes())

    # server = await asyncio.start_server(handle_client, host, port)
    server = await asyncio.start_server(partial(handle_client, _dilithium=dilithium), host, port)

    async with server:
        logger.info("Server started at %s:%s", host, port)
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(start_server("127.0.0.1", 8080))
