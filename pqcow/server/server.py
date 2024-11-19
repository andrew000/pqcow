from __future__ import annotations

import contextlib
import logging
import secrets
from asyncio import CancelledError
from typing import TYPE_CHECKING, cast

import msgspec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA3_512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from oqs import KeyEncapsulation, Signature  # type: ignore[import-untyped]
from websockets import ConnectionClosed, serve
from websockets.asyncio.server import Server as WS_Server
from websockets.asyncio.server import ServerConnection

from pqcow.func import receive_data, send_data
from pqcow.pq_types.answer_types import OK, Answer, Handshake
from pqcow.pq_types.request_types import SendHandshake, SendMessage, SendRequest

if TYPE_CHECKING:
    from types import FrameType

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


async def do_handshake(connection: ServerConnection) -> AESGCM:
    server_kem = KeyEncapsulation("Kyber512")
    public_key = server_kem.generate_keypair()

    handshake = msgspec.msgpack.encode(Handshake(public_key=public_key))
    await connection.send(handshake)

    send_handshake = msgspec.msgpack.decode(
        cast(bytes, await connection.recv(decode=False)),
        type=SendHandshake,
    )  # Wait for the client to send the encapsulated secret
    shared_secret = server_kem.decap_secret(send_handshake.encapsulated_secret)

    hkdf, salt = create_hkdf()
    shared_secret = AESGCM(hkdf.derive(shared_secret))

    await connection.send(salt)

    logger.info("%s Handshake successful", connection.write_limit)

    return shared_secret


class Server:
    def __init__(self, host: str, port: int, signature: Signature) -> None:
        """
        Initialize the Server Instance.

        :param host: The host, the server will run on.
        :type host: str
        :param port: The port, the server will run on.
        :type port: int
        :param signature: The signature of server.
        :type signature: Signature
        """
        self.host = host
        self.port = port
        self.signature = signature
        self.connections: set[ServerConnection] = set()
        self.server: WS_Server | None = None

    def signal_handler(self, signal_number: int, frame_type: FrameType | None) -> None:
        logger.info("Received signal %s, frame %s", signal_number, frame_type)
        cast(WS_Server, self.server).close(close_connections=True)

    async def start(self) -> None:
        self.server = await serve(handler=self.handler, host=self.host, port=self.port)

        with contextlib.suppress(CancelledError):
            await self.server.serve_forever()

    async def handler(self, connection: ServerConnection) -> None:
        self.connections.add(connection)

        try:
            shared_secret = await do_handshake(connection)

            async for message in connection:
                decrypted_data = await receive_data(shared_secret, cast(bytes, message))
                send_request: SendRequest = msgspec.msgpack.decode(decrypted_data, type=SendRequest)

                match send_request.request:
                    case SendMessage(text=text):
                        logger.info("%s Received message: %s", connection.remote_address, text)
                        await send_data(
                            connection=connection,
                            shared_secret=shared_secret,
                            data=msgspec.msgpack.encode(Answer(event_id=send_request.event_id, answer=OK())),
                        )

        except ConnectionClosed:
            logger.info("%s Connection closed by the client", connection.remote_address)

        except Exception as e:
            logger.exception(
                "%s An error occurred while handling the connection: %s",
                connection.remote_address,
                type(e).mro(),
            )

        finally:
            self.connections.remove(connection)


def create_hkdf() -> tuple[HKDF, bytes]:
    salt = secrets.token_bytes(16)
    hkdf = HKDF(
        algorithm=SHA3_512(),
        length=32,
        salt=salt,
        info=None,
    )
    return hkdf, salt
