# from __future__ import annotations
#
# import logging
# import threading
# from typing import TYPE_CHECKING, cast
# from urllib.parse import urlunparse
# from uuid import uuid4
#
# import msgspec
# from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# from cryptography.hazmat.primitives.hashes import SHA3_512
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from oqs import KeyEncapsulation, Signature  # type: ignore[import-untyped]
# from websockets import ConnectionClosed
# from websockets.sync.client import ClientConnection, connect
#
# from pqcow.client.base import BaseSyncClient
# from pqcow.func import pre_process_incom_data, prepare_data_to_send
# from pqcow.pq_types.answer_types import Answer, Handshake
# from pqcow.pq_types.request_types import REQUEST_TYPES, SendHandshake, SendMessage, SendRequest
#
# if TYPE_CHECKING:
#     from collections.abc import Generator
#     from uuid import UUID
#
# logger = logging.getLogger(__name__)
# logger.setLevel(logging.INFO)
#
#
# class SyncClient(BaseSyncClient):
#     def __init__(self, host: str, port: int, signature: Signature | None = None) -> None:
#         """
#         Initialize the Client Instance.
#
#         :param host: The host, the client will connect to.
#         :type host: str
#         :param port: The port, the client will connect to.
#         :type port: int
#         :param signature: The signature of client.
#         :type signature: Signature
#         """
#         self.address = host
#         self.port = port
#         self.signature = signature
#         self.events: dict[UUID, msgspec.Struct] = {}
#         self.lock = threading.Lock()
#         self.connection: ClientConnection | None = None
#         self.shared_secret: AESGCM | None = None
#
#     def connect(self) -> None:
#         self.connection = connect(
#             uri=urlunparse(("ws", f"{self.address}:{self.port}", "", "", "", "")),
#             compression=None,
#         )
#         self.do_handshake()
#
#     def close(self) -> None:
#         if not self.connection:
#             msg = "Client is not connected"
#             raise RuntimeError(msg)
#
#         self.connection.close()
#
#     def do_handshake(self) -> None:
#         handshake_bytes = cast(ClientConnection, self.connection).recv(decode=False)
#         handshake: Handshake = msgspec.msgpack.decode(cast(bytes, handshake_bytes),
#         type=Handshake)
#
#         client_kem = KeyEncapsulation("Kyber512")
#         encapsulated_secret, shared_secret = client_kem.encap_secret(handshake.kyber_public_key)
#         send_handshake = msgspec.msgpack.encode(SendHandshake(
#         encapsulated_secret=encapsulated_secret))
#
#         cast(ClientConnection, self.connection).send(send_handshake)
#
#         salt = cast(ClientConnection, self.connection).recv(decode=False)
#         # Wait for the server to send the salt
#         self.shared_secret = AESGCM(create_hkdf(cast(bytes, salt)).derive(shared_secret))
#
#         logger.info("Handshake with %s:%s successful", self.address, self.port)
#
#     def __iter__(self) -> Generator[tuple[Answer, msgspec.Struct | None]]:
#         if not self.connection:
#             msg = "Client is not connected"
#             raise RuntimeError(msg)
#
#         if not self.shared_secret:
#             msg = "Shared secret is not established"
#             raise RuntimeError(msg)
#
#         while True:
#             with self.lock:
#                 try:
#                     message = self.connection.recv(timeout=0.1)
#                 except TimeoutError:
#                     continue
#                 except ConnectionClosed:
#                     logger.info("Connection closed by the server")
#                     break
#                 except Exception as e:
#                     logger.exception("An error occurred while receiving message: %s",
#                     type(e).mro())
#                     continue
#
#                 try:
#                     data = pre_process_incom_data(shared_secret=self.shared_secret,
#                     data=cast(bytes, message))
#
#                 except Exception as e:
#                     logger.exception("An error occurred while receiving data: %s", type(e).mro())
#                     continue
#
#                 answer = msgspec.msgpack.decode(data, type=Answer)
#
#                 try:
#                     event_info = self.events[answer.event_id]
#                 except KeyError:
#                     logger.warning("Event with ID %s not found", answer.event_id)
#                     yield answer, None
#                 except Exception as e:
#                     logger.exception("An error occurred while processing the answer: %s",
#                     type(e).mro())
#                     yield answer, None
#                 else:
#                     self.events.pop(answer.event_id, None)
#                     yield answer, event_info
#
#     def send_request(self, request: REQUEST_TYPES) -> None:
#         if not self.connection:
#             msg = "Client is not connected"
#             raise RuntimeError(msg)
#
#         if not self.shared_secret:
#             msg = "Shared secret is not established"
#             raise RuntimeError(msg)
#
#         event_id = uuid4()
#         send_request = SendRequest(event_id=event_id, request=request)
#         self.events[event_id] = send_request
#
#         data_to_send = prepare_data_to_send(
#             shared_secret=self.shared_secret,
#             data=msgspec.msgpack.encode(send_request),
#         )
#
#         self.connection.send(data_to_send)
#
#     def send_message(self, chat_id: int | str, text: str) -> None:
#         self.send_request(SendMessage(peer_id=chat_id, text=text))
#
#
# def create_hkdf(salt: bytes) -> HKDF:
#     return HKDF(
#         algorithm=SHA3_512(),
#         length=32,
#         salt=salt,
#         info=None,
#     )
