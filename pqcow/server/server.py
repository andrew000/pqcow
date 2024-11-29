from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from typing import TYPE_CHECKING, Literal, cast

import msgspec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA3_512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from oqs import KeyEncapsulation, Signature  # type: ignore[import-untyped]
from websockets import ConnectionClosed, serve

from pqcow.func import pre_process_incom_data, prepare_data_to_send
from pqcow.pq_types.answer_types import OK, Answer, Error, Handshake
from pqcow.pq_types.answer_types.resolved_user import ResolvedUser
from pqcow.pq_types.request_types import SendHandshake, SendMessage, SendRequest
from pqcow.pq_types.request_types.chat_list_main import ChatListMain
from pqcow.pq_types.request_types.register_request import RegisterRequest
from pqcow.pq_types.request_types.resolve_user import ResolveUserByDilithium
from pqcow.pq_types.signed_data import SignedData
from pqcow.server.client_data import ClientData, UnregisteredClientData
from pqcow.server.db.base import init_db
from pqcow.server.exceptions import ChatNotFoundError, SignatureVerificationError

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
    from websockets.asyncio.server import Server as WS_Server
    from websockets.asyncio.server import ServerConnection

    from pqcow.server.db.db import ServerDatabase
    from pqcow.server.db.models.messages import MessagesModel
    from pqcow.server.db.models.users import UserModel

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


async def do_handshake(
    *,
    connection: ServerConnection,
    db: ServerDatabase[async_sessionmaker[AsyncSession]],
    signature: Signature,
    dilithium_public_key: bytes,
) -> UnregisteredClientData | ClientData:
    server_kem = KeyEncapsulation("Kyber512")
    kyber_public_key = server_kem.generate_keypair()

    handshake = msgspec.msgpack.encode(
        Handshake(
            kyber_public_key=kyber_public_key,
            dilithium_public_key=dilithium_public_key,
        ),
    )

    await connection.send(
        msgspec.msgpack.encode(SignedData(data=handshake, sign=signature.sign(handshake))),
    )

    # Wait for the client to send the encapsulated secret
    signed_data = msgspec.msgpack.decode(
        cast(bytes, await connection.recv(decode=False)),
        type=SignedData,
    )
    send_handshake = msgspec.msgpack.decode(
        signed_data.data,
        type=SendHandshake,
    )

    is_ok = signature.verify(
        message=signed_data.data,
        signature=signed_data.sign,
        public_key=send_handshake.dilithium_public_key,
    )

    if not is_ok:
        raise SignatureVerificationError(dilithium_public_key=send_handshake.dilithium_public_key)

    shared_secret = server_kem.decap_secret(send_handshake.encapsulated_secret)

    shared_secret = AESGCM(create_hkdf().derive(shared_secret))
    logger.info("%s Handshake successful", connection.remote_address)

    async with db.sessionmaker() as session:
        user = await db.resolve_user_by_dilithium(
            session=session,
            initiator_id=None,
            dilithium_public_key=send_handshake.dilithium_public_key,
        )

    if not user:
        return UnregisteredClientData(
            dilithium_public_key=send_handshake.dilithium_public_key,
            shared_secret=shared_secret,
        )

    return ClientData(
        user_id=user.id,
        username=user.username,
        dilithium_public_key=send_handshake.dilithium_public_key,
        shared_secret=shared_secret,
    )


class Server:
    def __init__(
        self,
        host: str,
        port: int,
        signature: Signature,
        dilithium_public_key: bytes,
        db: ServerDatabase[async_sessionmaker[AsyncSession]],
    ) -> None:
        """
        Initialize the Server Instance.

        :param host: The host, the server will run on.
        :type host: str
        :param port: The port, the server will run on.
        :type port: int
        :param signature: The signature of server.
        :type signature: Signature
        :param dilithium_public_key: The dilithium public key of server.
        :type dilithium_public_key: bytes
        :param db: The database instance.
        :type db: ServerDatabase[async_sessionmaker[AsyncSession]]
        """
        self.host = host
        self.port = port
        self.signature = signature
        self.dilithium_public_key = dilithium_public_key
        self.db = db
        self.connections: set[ServerConnection] = set()
        self.ws: WS_Server | None = None

    async def start(self) -> None:
        await init_db(self.db.engine)

        self.ws = await serve(handler=self.handler, host=self.host, port=self.port)

        with suppress(asyncio.CancelledError):
            async with self.ws:
                await asyncio.get_running_loop().create_future()  # Run forever

        await self.db.close()

    async def handler(self, connection: ServerConnection) -> None:
        self.connections.add(connection)

        try:
            client_data = await do_handshake(
                connection=connection,
                db=self.db,
                signature=self.signature,
                dilithium_public_key=self.dilithium_public_key,
            )

            if isinstance(client_data, UnregisteredClientData):
                logger.info(
                    "%s User not found. Waiting for registration",
                    connection.remote_address,
                )
                client_data: ClientData | Literal[False] = await self._registration(
                    connection=connection,
                    client_data=client_data,
                )

                if not client_data:
                    return

            async for message in connection:
                signed_data: SignedData = pre_process_incom_data(
                    shared_secret=client_data.shared_secret,
                    data=cast(bytes, message),
                )
                self._verify_signature(signed_data, cast(ClientData, client_data))

                send_request: SendRequest = msgspec.msgpack.decode(
                    signed_data.data,
                    type=SendRequest,
                )

                match send_request.request:
                    case SendMessage(user_id=user_id, text=text):
                        logger.info(
                            "%s Received SendMessage(user_id=%s, text=%s)",
                            connection.remote_address,
                            user_id,
                            text,
                        )

                        try:
                            await self.send_message(
                                chat_id=1,
                                sender_id=cast(ClientData, client_data).user_id,
                                receiver_id=user_id,
                                message=text,
                            )
                        except ChatNotFoundError:
                            data_to_send = prepare_data_to_send(
                                shared_secret=cast(ClientData, client_data).shared_secret,
                                sign=self.signature,
                                data=Answer(
                                    event_id=send_request.event_id,
                                    answer=Error(code=2, message="Chat not found"),
                                ),
                            )
                            await connection.send(data_to_send)
                            continue

                        data_to_send = prepare_data_to_send(
                            shared_secret=client_data.shared_secret,
                            sign=self.signature,
                            data=Answer(event_id=send_request.event_id, answer=OK(data=None)),
                        )
                        await connection.send(data_to_send)

                    # case RegisterRequest():
                    #     logger.info("%s Received RegisterRequest", connection.remote_address)
                    #     data_to_send = prepare_data_to_send(
                    #         shared_secret=client_data.shared_secret,
                    #         sign=self.signature,
                    #         data=Answer(
                    #                 event_id=send_request.event_id,
                    #                 answer=Error(code=1, message="Already registered"),
                    #         ),
                    #     )
                    #     await connection.send(data_to_send)

                    case ResolveUserByDilithium(dilithium_public_key=dilithium_public_key):
                        logger.info(
                            "%s Received ResolveUserByDilithium(dilithium_public_key=%s)",
                            connection.remote_address,
                            dilithium_public_key,
                        )
                        user = await self.resolve_user_by_dilithium(
                            initiator_id=cast(ClientData, client_data).user_id,
                            dilithium_public_key=dilithium_public_key,
                        )

                        if not user:
                            data = prepare_data_to_send(
                                shared_secret=client_data.shared_secret,
                                sign=self.signature,
                                data=Answer(
                                    event_id=send_request.event_id,
                                    answer=Error(code=1, message="User not found"),
                                ),
                            )

                            await connection.send(data)
                            continue

                        data = prepare_data_to_send(
                            shared_secret=client_data.shared_secret,
                            sign=self.signature,
                            data=Answer(
                                event_id=send_request.event_id,
                                answer=OK(
                                    data=ResolvedUser(
                                        id=user.id,
                                        username=user.username,
                                        dilithium_public_key=user.dilithium_public_key,
                                    ),
                                ),
                            ),
                        )

                        await connection.send(data)

                    case ChatListMain():
                        logger.info("%s Received ChatListMain", connection.remote_address)

                        # self.db.chat_list_main(user_id=client_data.user_id)
                        #
                        # data_to_send = prepare_data_to_send(
                        #     shared_secret=client_data.shared_secret,
                        #     data=msgspec.msgpack.encode(Answer(event_id=send_request.event_id,
                        #     answer=OK())),
                        # )
                        # await connection.send(data_to_send)

        except ConnectionClosed:
            logger.info("%s Connection closed by the client", connection.remote_address)

        except msgspec.ValidationError as e:
            logger.exception("%s Invalid data received: %s", connection.remote_address, e.args)
            await connection.close(reason="Invalid data received")

        except SignatureVerificationError as e:
            logger.exception(
                "%s %s Signature verification failed",
                connection.remote_address,
                e.args,
            )
            await connection.close(reason="Signature verification failed")

        except Exception as e:
            logger.exception(
                "%s An error occurred while handling the connection: %s",
                connection.remote_address,
                e.args,
            )

        finally:
            self.connections.discard(connection)

    def _verify_signature(
        self,
        signed_data: SignedData,
        client_data: ClientData,
    ) -> Literal[True]:
        is_ok = self.signature.verify(
            message=signed_data.data,
            signature=signed_data.sign,
            public_key=client_data.dilithium_public_key,
        )

        if not is_ok:
            raise SignatureVerificationError(dilithium_public_key=client_data.dilithium_public_key)

        return True

    async def _registration(
        self,
        *,
        connection: ServerConnection,
        client_data: UnregisteredClientData,
    ) -> ClientData | Literal[False]:
        signed_data = pre_process_incom_data(
            shared_secret=client_data.shared_secret,
            data=cast(bytes, await connection.recv()),
        )

        is_ok = self.signature.verify(
            message=signed_data.data,
            signature=signed_data.sign,
            public_key=client_data.dilithium_public_key,
        )

        if not is_ok:
            logger.error("%s Signature verification failed", connection.remote_address)
            await connection.close(reason="Signature verification failed")
            return False

        try:
            send_request = msgspec.msgpack.decode(
                signed_data.data,
                type=SendRequest,
            )
            if not isinstance(send_request.request, RegisterRequest):
                logger.error("%s Invalid data received. Register wanted", connection.remote_address)
                return False

        except msgspec.ValidationError as e:
            logger.exception(
                "%s Invalid data received. Register wanted: %s",
                connection.remote_address,
                e.args,
            )
            await connection.close(reason="Invalid data received. Register wanted")
            return False

        async with self.db.sessionmaker() as session:
            user = await self.db.register_user(
                session=session,
                username=send_request.request.username,
                dilithium_public_key=client_data.dilithium_public_key,
            )

        return ClientData(
            user_id=user.id,
            username=send_request.request.username,
            dilithium_public_key=client_data.dilithium_public_key,
            shared_secret=client_data.shared_secret,
        )

    async def send_message(
        self,
        chat_id: int,
        sender_id: int,
        receiver_id: int,
        message: str,
    ) -> MessagesModel:
        async with self.db.sessionmaker() as session:
            return await self.db.send_message(
                session=session,
                chat_id=chat_id,
                sender_id=sender_id,
                receiver_id=receiver_id,
                text=message,
                signature=self.signature.sign(message.encode("utf-8")),
            )

    async def resolve_user_by_dilithium(
        self,
        initiator_id: int,
        dilithium_public_key: bytes,
    ) -> UserModel | None:
        async with self.db.sessionmaker() as session:
            return await self.db.resolve_user_by_dilithium(
                session=session,
                initiator_id=initiator_id,
                dilithium_public_key=dilithium_public_key,
            )


def create_hkdf() -> HKDF:
    return HKDF(
        algorithm=SHA3_512(),
        length=32,
        salt=None,
        info=b"pqcow",
    )
