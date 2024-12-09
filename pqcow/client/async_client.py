from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Literal, cast
from urllib.parse import urlunparse
from uuid import uuid4

import msgspec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA3_512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from oqs import KeyEncapsulation, Signature  # type: ignore[import-untyped]
from websockets import ConnectionClosed, connect
from websockets.asyncio.client import ClientConnection

from pqcow.client.base import BaseAsyncClient
from pqcow.client.db.base import Base
from pqcow.pq_func import pre_process_incom_data, prepare_data_to_send
from pqcow.pq_types.answer_types import Answer, Handshake
from pqcow.pq_types.request_types import REQUEST_TYPES, SendHandshake, SendMessage, SendRequest
from pqcow.pq_types.request_types.chat_list import ChatList
from pqcow.pq_types.request_types.poll_messages import PollMessages
from pqcow.pq_types.request_types.register_request import RegisterRequest
from pqcow.pq_types.request_types.resolve_user import ResolveUserByDilithium
from pqcow.pq_types.signed_data import SignedData
from pqcow.server.exceptions import SignatureVerificationError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from pqcow.client.db.db import ClientDatabase

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class AsyncClient(BaseAsyncClient):
    def __init__(
        self,
        host: str,
        port: int,
        signature: Signature,
        public_key: bytes,
        username: str,
        db: ClientDatabase[async_sessionmaker[AsyncSession]],
        server_dilithium_public_key: bytes | None = None,
        force_retrieve_server_public_key: bool = False,
    ) -> None:
        """
        Initialize the Client Instance.

        :param host: The host, the client will connect to.
        :type host: str
        :param port: The port, the client will connect to.
        :type port: int
        :param signature: The signature of client.
        :type signature: Signature
        :param public_key: The public key of client.
        :type public_key: bytes
        :param username: The username of client.
        :type username: str
        :param db: The database instance.
        :type db: ClientDatabase[async_sessionmaker[AsyncSession]]
        :param server_dilithium_public_key: The public key of server.
        :type server_dilithium_public_key: bytes | None
        :param force_retrieve_server_public_key: If True, the client will retrieve the server
        public key.
        :type force_retrieve_server_public_key: bool
        """
        self.address = host
        self.port = port
        self.signature = signature
        self.public_key = public_key
        self.username = username
        self.db = db
        self.server_dilithium_public_key: bytes | None = server_dilithium_public_key
        self.force_retrieve_server_public_key = force_retrieve_server_public_key
        self.user_id: int | None = None
        self.events: dict[UUID, msgspec.Struct] = {}
        self.lock = asyncio.Lock()
        self.connection: ClientConnection | None = None
        self.shared_secret: AESGCM | None = None

    async def connect(self) -> None:
        await self.db.init_db(base_model=Base)

        self.connection = await connect(
            uri=urlunparse(("ws", f"{self.address}:{self.port}", "", "", "", "")),
            compression=None,
        )
        await self.do_handshake(self.signature)

    async def close(self) -> None:
        if not self.connection:
            msg = "Client is not connected"
            raise RuntimeError(msg)

        await self.connection.close()
        await self.connection.wait_closed()

        await self.db.close()

    async def do_handshake(self, signature: Signature) -> None:
        signed_data = msgspec.msgpack.decode(
            cast(bytes, await cast(ClientConnection, self.connection).recv(decode=False)),
            type=SignedData,
        )
        handshake: Handshake = msgspec.msgpack.decode(signed_data.data, type=Handshake)

        if handshake.dilithium_public_key != self.server_dilithium_public_key:
            if self.force_retrieve_server_public_key:
                self.server_dilithium_public_key = handshake.dilithium_public_key
            else:
                msg = "Server public key does not match the one provided"
                raise RuntimeError(msg)

        is_ok = signature.verify(
            message=signed_data.data,
            signature=signed_data.sign,
            public_key=self.server_dilithium_public_key,
        )

        if not is_ok:
            msg = "Handshake failed"
            raise RuntimeError(msg)

        client_kem = KeyEncapsulation("Kyber512")
        encapsulated_secret, shared_secret = client_kem.encap_secret(handshake.kyber_public_key)
        send_handshake = msgspec.msgpack.encode(
            SendHandshake(
                encapsulated_secret=encapsulated_secret,
                dilithium_public_key=self.public_key,
                username=self.username,
                sign=signature.sign(encapsulated_secret),
            ),
        )
        signed_data = SignedData(data=send_handshake, sign=signature.sign(send_handshake))

        await cast(ClientConnection, self.connection).send(msgspec.msgpack.encode(signed_data))

        self.shared_secret = AESGCM(create_hkdf().derive(shared_secret))

        logger.info("Handshake with %s:%s successful", self.address, self.port)

    async def __aiter__(self) -> AsyncIterator[tuple[Answer, msgspec.Struct | None]]:
        if not self.connection:
            msg = "Client is not connected"
            raise RuntimeError(msg)

        if not self.shared_secret:
            msg = "Shared secret is not established"
            raise RuntimeError(msg)

        while True:
            async with self.lock:
                try:
                    task = asyncio.wait_for(self.connection.recv(), timeout=0.1)
                    message = await task
                except TimeoutError:
                    continue
                except ConnectionClosed:
                    logger.info(
                        "Connection closed by the server. Reason: %s",
                        self.connection.close_reason,
                    )
                    break
                except asyncio.CancelledError:
                    logger.info("Connection closed by the client")
                    break
                except Exception as e:
                    logger.exception("An error occurred while receiving message: %s", e.args)
                    continue

                try:
                    signed_data = pre_process_incom_data(
                        shared_secret=self.shared_secret,
                        data=cast(bytes, message),
                    )

                except Exception as e:
                    logger.exception("An error occurred while receiving data: %s", e.args)
                    continue

                try:
                    self._verify_signature(signed_data)
                except SignatureVerificationError as e:
                    logger.exception("An error occurred while verifying the signature: %s", e.args)
                    continue

                answer = msgspec.msgpack.decode(signed_data.data, type=Answer)

                try:
                    event_info = self.events[answer.event_id]
                except KeyError:
                    logger.warning("Event with ID %s not found", answer.event_id)
                    yield answer, None
                except Exception as e:
                    logger.exception(
                        "An error occurred while processing the answer: %s",
                        e.args,
                    )
                    self.events.pop(answer.event_id, None)
                    yield answer, None
                else:
                    self.events.pop(answer.event_id, None)
                    yield answer, event_info

    def _verify_signature(self, signed_data: SignedData) -> Literal[True]:
        is_ok = self.signature.verify(
            message=signed_data.data,
            signature=signed_data.sign,
            public_key=self.server_dilithium_public_key,
        )

        if not is_ok:
            raise SignatureVerificationError(dilithium_public_key=self.public_key)

        return True

    async def __call__(self, request: REQUEST_TYPES) -> None:
        if not self.connection:
            msg = "Client is not connected"
            raise RuntimeError(msg)

        if not self.shared_secret:
            msg = "Shared secret is not established"
            raise RuntimeError(msg)

        async with self.lock:
            event_id = uuid4()
            send_request = SendRequest(event_id=event_id, request=request)
            self.events[event_id] = send_request

            data_to_send = prepare_data_to_send(
                shared_secret=self.shared_secret,
                data=send_request,
                sign=self.signature,
            )
            await self.connection.send(data_to_send)

    async def register(self) -> None:
        await self(RegisterRequest(username=self.username))

    async def resolve_user(self, dilithium_public_key: bytes) -> None:
        await self(ResolveUserByDilithium(dilithium_public_key=dilithium_public_key))

    async def send_message(self, user_id: int, text: str) -> None:
        await self(
            SendMessage(user_id=user_id, sign=self.signature.sign(text.encode()), text=text),
        )

    async def chat_list(self) -> None:
        await self(ChatList())

    async def poll_messages(self, chat_id: int) -> None:
        async with self.db.sessionmaker() as session:
            messages = await self.db.get_messages_by_chat_id(
                session=session,
                chat_id=chat_id,
                limit=1,
            )

            last_message_id = 0 if not messages else messages[-1].message_id

        await self(PollMessages(chat_id=chat_id, last_message_id=last_message_id))


def create_hkdf() -> HKDF:
    return HKDF(
        algorithm=SHA3_512(),
        length=32,
        salt=None,
        info=b"pqcow",
    )
