from __future__ import annotations

import logging
from typing import TYPE_CHECKING, cast
from urllib.parse import urlunparse

import msgspec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA3_512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from oqs import KeyEncapsulation, Signature  # type: ignore[import-untyped]
from websockets import connect
from websockets.asyncio.client import ClientConnection

from pqcow_func import receive_data, send_data
from pqcow_types.answer_types import Answer, Handshake
from pqcow_types.request_types import REQUEST_TYPES, SendHandshake, SendMessage, SendRequest

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class Client:
    def __init__(self, host: str, port: int, signature: Signature | None = None) -> None:
        """
        Initialize the Client Instance.

        :param host: The host, the client will connect to.
        :type host: str
        :param port: The port, the client will connect to.
        :type port: int
        :param signature: The signature of client.
        :type signature: Signature
        """
        self.address = host
        self.port = port
        self.signature = signature
        self.connection: ClientConnection | None = None
        self.shared_secret: AESGCM | None = None

    async def connect(self) -> None:
        self.connection = await connect(uri=urlunparse(("ws", f"{self.address}:{self.port}", "", "", "", "")))
        await self.do_handshake()

    async def do_handshake(self) -> None:
        handshake_bytes = await cast(ClientConnection, self.connection).recv(decode=False)
        handshake: Handshake = msgspec.msgpack.decode(cast(bytes, handshake_bytes), type=Handshake)

        client_kem = KeyEncapsulation("Kyber512")
        encapsulated_secret, shared_secret = client_kem.encap_secret(handshake.public_key)
        send_handshake = msgspec.msgpack.encode(SendHandshake(encapsulated_secret=encapsulated_secret))

        await cast(ClientConnection, self.connection).send(send_handshake)

        salt = await cast(ClientConnection, self.connection).recv(decode=False)  # Wait for the server to send the salt
        self.shared_secret = AESGCM(create_hkdf(cast(bytes, salt)).derive(shared_secret))

        logger.info("Handshake with %s:%s successful", self.address, self.port)

    async def __aiter__(self) -> AsyncIterator[Answer]:
        if not self.connection:
            msg = "Client is not connected"
            raise RuntimeError(msg)

        if not self.shared_secret:
            msg = "Shared secret is not established"
            raise RuntimeError(msg)

        async for message in self.connection:
            try:
                data = await receive_data(key=self.shared_secret, data=cast(bytes, message))

            except Exception as e:
                logger.exception("An error occurred while receiving data: %s", type(e).mro())
                continue

            else:
                yield msgspec.msgpack.decode(data, type=Answer)

    async def close(self) -> None:
        if not self.connection:
            msg = "Client is not connected"
            raise RuntimeError(msg)

        await self.connection.close()
        await self.connection.wait_closed()

    async def send_request(self, request: REQUEST_TYPES) -> None:
        if not self.connection:
            msg = "Client is not connected"
            raise RuntimeError(msg)

        if not self.shared_secret:
            msg = "Shared secret is not established"
            raise RuntimeError(msg)

        request = SendRequest(request=request)
        await send_data(connection=self.connection, key=self.shared_secret, data=msgspec.msgpack.encode(request))

    async def send_message(self, chat_id: int | str, text: str) -> None:
        await self.send_request(SendMessage(chat_id=chat_id, text=text))


def create_hkdf(salt: bytes) -> HKDF:
    return HKDF(
        algorithm=SHA3_512(),
        length=32,
        salt=salt,
        info=None,
    )
