# from __future__ import annotations
#
# import logging
# import threading
# from contextlib import suppress
# from enum import Enum
# from pathlib import Path
# from typing import TYPE_CHECKING
#
# import oqs  # type: ignore[import-untyped]
# from websockets import ConnectionClosed, ConnectionClosedError
#
# from pqcow.client.sync_client import SyncClient
# from pqcow.key_storage.key_storage import JSONKeyStorage
#
# if TYPE_CHECKING:
#     from key_storage.base import Key
#
# logging.basicConfig(format="%(asctime)s %(message)s", level=logging.INFO)
# logger = logging.getLogger(__name__)
#
#
# class CloseReason(Enum):
#     CLIENT_CLOSED = 0
#     SERVER_CLOSED = 1
#     TASK_CANCELLED = 2
#     ERROR = 3
#
#
# def create_dilithium_keypair() -> bytes:
#     dilithium = oqs.Signature("Dilithium3")
#     dilithium.generate_keypair()
#     return dilithium.export_secret_key()
#
#
# def sender(client: SyncClient, close_reason: list[CloseReason]) -> None:
#     try:
#         while True:
#             message = input("Enter message: ")
#
#             if message == "/exit":
#                 client.close()
#                 close_reason[0] = CloseReason.CLIENT_CLOSED
#                 break
#
#             try:
#                 client.send_message(1, message)
#
#             except ConnectionClosed:
#                 close_reason[0] = CloseReason.SERVER_CLOSED
#                 break
#
#     except Exception as e:
#         logger.exception("An error occurred while sending message: %s", type(e).mro())
#         close_reason[0] = CloseReason.ERROR
#
#
# def start_client(host: str, port: int, identity: str) -> CloseReason:
#     storage = JSONKeyStorage(Path("storage.enc"), "salt")
#
#     with suppress(ValueError):
#         storage.create_storage("password")
#
#     storage.load_storage("password")
#
#     try:
#         key: Key = storage.get_key(identity)
#     except KeyError:
#         logger.info("Identity key for `%s` not found. Would you like to create one?", identity)
#         create = input("[Y/n]: ")
#
#         if create.casefold() != "y":
#             return CloseReason.ERROR
#
#         logger.info("Creating Identity key for `%s`...", identity)
#
#         storage.set_key(identity, create_dilithium_keypair())
#         storage.save_storage("password")
#
#         logger.info("Identity key for `%s` created and saved", identity)
#
#         key = storage.get_key(identity)
#
#     client = SyncClient(host, port, signature=oqs.Signature("Dilithium3", key.key))
#
#     try:
#         client.connect()
#     except ConnectionRefusedError:
#         logger.info("Could not connect to server at %s:%s", host, port)
#         return CloseReason.ERROR
#
#     _close_reason = [CloseReason.ERROR]
#     _thread = threading.Thread(target=sender, args=(client, _close_reason))
#     _thread.start()
#
#     try:
#         for answer in client:
#             logger.info("Received answer: %s", answer)
#
#     except ConnectionClosedError:
#         logger.info("Connection closed by the server")
#
#     _thread.join()
#
#     return _close_reason[0]
#
#
# def main() -> None:
#     while True:
#         close_reason = start_client("127.0.0.1", 8080, identity="Andrew")
#
#         match close_reason:
#             case CloseReason.CLIENT_CLOSED | CloseReason.TASK_CANCELLED:
#                 break
#
#             case CloseReason.SERVER_CLOSED:
#                 reconnect = input("Reconnect to server? [N/y]: ")
#
#                 if reconnect.lower() != "y":
#                     break
#
#             case CloseReason.ERROR:
#                 reconnect = input("Reconnect to server? [N/y]: ")
#
#                 if reconnect.lower() != "y":
#                     break
#
#             case _:
#                 break
#
#     logger.info("Exiting client...")
#
#
# if __name__ == "__main__":
#     main()
