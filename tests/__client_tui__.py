# from __future__ import annotations
#
# import asyncio
# import logging
# import random
# from contextlib import suppress
# from enum import Enum
# from typing import TYPE_CHECKING, Self
#
# import oqs  # type: ignore[import-untyped]
# from cryptography.fernet import InvalidToken
# from rich.text import TextType
# from textual import events, on
# from textual.app import App, ComposeResult
# from textual.containers import Container, VerticalScroll
# from textual.css.query import NoMatches
# from textual.message import Message
# from textual.reactive import reactive
# from textual.widget import Widget
# from textual.widgets import Footer, Header, Input, Static
# from websockets import ConnectionClosed, ConnectionClosedError
#
# from pqcow.client import AsyncClient
# from pqcow.key_storage.key_storage import JSONKeyStorage
# from pqcow.pq_types.answer_types import Error
# from pqcow.pq_types.answer_types.resolved_user import ResolvedUser
#
# if TYPE_CHECKING:
#     from pathlib import Path
#
#     from pqcow.key_storage.base import UserIdent
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
#     LOCAL_ERROR = 4
#
#
# def create_dilithium_keypair() -> tuple[bytes, bytes]:
#     dilithium = oqs.Signature("Dilithium3")
#     public_key = dilithium.generate_keypair()
#     return public_key, dilithium.export_secret_key()
#
#
# class ChatItem(Widget, can_focus=True):
#     CSS_PATH = "dock_layout1_sidebar.tcss"
#
#     title: reactive[TextType] = reactive[TextType]("")
#
#     class Pressed(Message):
#         def __init__(self, chat_item: ChatItem) -> None:
#             self.chat_item = chat_item
#             super().__init__()
#
#         @property
#         def control(self) -> ChatItem:
#             return self.chat_item
#
#     def __init__(
#         self,
#         chat_id: int,
#         title: str,
#         *,
#         name: str | None = None,
#         id: str | None = None,
#         classes: str | None = None,
#         disabled: bool = False,
#     ) -> None:
#         super().__init__(name=name, id=id, classes=classes, disabled=disabled)
#         self.chat_id = chat_id
#         self.title = title
#
#     def render(self) -> str:
#         return self.title
#
#     async def _on_click(self, event: events.Click) -> None:
#         event.stop()
#         await self.press()
#
#     async def press(self) -> Self:
#         if self.disabled or not self.display:
#             return self
#         self.post_message(ChatItem.Pressed(self))
#         return self
#
#     async def action_press(self) -> None:
#         """Activate a press of the button."""
#         await self.press()
#
#
# class PQCowClient(App):
#     CSS_PATH = "dock_layout1_sidebar.tcss"
#
#     current_chat_id: int = reactive(-1)
#
#     def __init__(self) -> None:
#         super().__init__()
#         self.current_chat_id: int = -1
#
#     def on_mount(self) -> None: ...
#
#     def compose(self) -> ComposeResult:
#         yield Header()
#
#         with Container(id="app-grid"):
#             with VerticalScroll(id="chat-list"):
#                 for number in range(5):
#                     yield ChatItem(
#                         number,
#                         f"Chat {number}",
#                         id=f"chat-{number}",
#                         classes="chat-item",
#                     )
#
#             with Container(id="right-panel"):
#                 with VerticalScroll(id="messages-list"):
#                     yield Static("Select a chat to start messaging...", id="select-chat-tip")
#
#                 yield Input(
#                     placeholder="Enter message...",
#                     id="message-input",
#                     max_length=1024,
#                     disabled=True,
#                 )
#
#         yield Footer()
#
#     @on(ChatItem.Pressed)
#     def chat_item_pressed(self, event: ChatItem.Pressed) -> None:
#         self.current_chat_id = event.control.chat_id
#         self.query_one("#message-input", expect_type=Input).disabled = False
#
#         messages_list = self.query_one("#messages-list", expect_type=VerticalScroll)
#         with suppress(NoMatches):
#             messages_list.query_one("#select-chat-tip", expect_type=Static).remove()
#
#         for message in messages_list.walk_children(Static):
#             message.remove()
#
#         messages_list.mount_all(
#             [
#                 random.choice(
#                     [
#                         Static(
#                             f"[{number}] Message will appear here...",
#                             classes="my-message",
#                         ),
#                         Static(
#                             f"[{number}] Other user's message will appear here...",
#                             classes="other-message",
#                         ),
#                     ],
#                 )
#                 for number in range(30)
#             ],
#         )
#
#         messages_list.scroll_end()
#
#
# def recv_user_input(text: str) -> str:
#     return input(text)
#
#
# async def sender(client: AsyncClient) -> CloseReason:
#     try:
#         while True:
#             message = await asyncio.to_thread(recv_user_input, "Enter command: ")
#             try:
#                 match message:
#                     case "/exit":
#                         await client.close()
#                         return CloseReason.CLIENT_CLOSED
#
#                     case "/resolve":
#                         dilithium_public_key_hex: str = await asyncio.to_thread(
#                             recv_user_input,
#                             "Enter dilithium public key: ",
#                         )
#                         try:
#                             await client.resolve_user(
#                                 bytes.fromhex(dilithium_public_key_hex.removeprefix("0x")),
#                             )
#                         except ValueError:
#                             logger.exception("Invalid dilithium public key")
#                             continue
#
#                     case "/send":
#                         user_id = int(await asyncio.to_thread(recv_user_input, "Enter user id: "))
#                         message = await asyncio.to_thread(recv_user_input, "Enter message: ")
#                         await client.send_message(user_id, message)
#
#             except ConnectionClosed as e:
#                 logger.info("Connection closed by the server. Reason: %s", e.rcvd.reason)
#                 return CloseReason.SERVER_CLOSED
#
#             await asyncio.sleep(0.1)
#
#     except asyncio.CancelledError:
#         logger.info("Sender task was cancelled")
#         return CloseReason.TASK_CANCELLED
#
#     except Exception as e:
#         logger.exception("An error occurred while sending message: %s", e.args)
#         return CloseReason.ERROR
#
#
# async def start_client(
#     host: str,
#     port: int,
#     user_ident_name: str,
#     server_ident_name: str,
#     storage_path: Path,
#     storage_key: str | bytes,
# ) -> CloseReason:
#     storage = JSONKeyStorage(storage_path)
#
#     with suppress(ValueError):
#         storage.create_storage(storage_key)
#
#     try:
#         storage.load_storage(storage_key)
#     except InvalidToken:
#         logger.exception("Invalid storage key")
#         return CloseReason.LOCAL_ERROR
#
#     try:
#         user_ident: UserIdent = storage.get_user_ident(user_ident_name)
#     except KeyError:
#         logger.info(
#             "Identity key for user `%s` not found. Would you like to create one?",
#             user_ident_name,
#         )
#         create = input("[Y/n]: ")
#
#         if create.casefold() != "y":
#             return CloseReason.ERROR
#
#         logger.info("Creating Identity key for user `%s`...", user_ident_name)
#
#         public_key, private_key = create_dilithium_keypair()
#         storage.set_user_ident(name=user_ident_name, public_key=public_key,
#         private_key=private_key)
#         storage.save_storage(storage_key)
#         user_ident = storage.get_user_ident(user_ident_name)
#
#         logger.info("Identity key for user `%s` created and saved", user_ident_name)
#
#     try:
#         server_ident = storage.get_server_ident(server_ident_name)
#     except KeyError:
#         logger.info(
#             "Identity key for server `%s` not found. Would you like to add one?",
#             server_ident_name,
#         )
#         create = input("[Y/n]: ")
#
#         if create.casefold() != "y":
#             return CloseReason.ERROR
#
#         server_ident_input = input("Enter server dilithium public key in hex: ")
#
#         try:
#             server_ident_bytes = bytes.fromhex(server_ident_input)
#         except ValueError:
#             logger.exception("Invalid dilithium public key")
#             return CloseReason.ERROR
#
#         storage.set_server_ident(name=server_ident_name, public_key=server_ident_bytes)
#         storage.save_storage(storage_key)
#         server_ident = storage.get_server_ident(server_ident_name)
#
#         logger.info("Identity key for server `%s` added and saved", server_ident_name)
#
#     logger.info(
#         "Loaded Identity key for user `%s`; %s",
#         user_ident,
#         user_ident.dilithium_public_key.hex(),
#     )
#     logger.info(
#         "Loaded Identity key for server `%s`; %s",
#         server_ident_name,
#         server_ident.dilithium_public_key.hex(),
#     )
#
#     client = AsyncClient(
#         host=host,
#         port=port,
#         signature=oqs.Signature("Dilithium3", user_ident.dilithium_private_key),
#         public_key=user_ident.dilithium_public_key,
#         username=user_ident_name,
#         server_dilithium_public_key=server_ident.dilithium_public_key,
#     )
#
#     try:
#         await client.connect()
#     except ConnectionRefusedError:
#         logger.info("Could not connect to server at %s:%s", host, port)
#         return CloseReason.ERROR
#
#     try:
#         await client.register()
#     except Exception as e:
#         logger.exception("An error occurred while registering: %s", type(e).mro())
#         return CloseReason.ERROR
#
#     _task = asyncio.create_task(sender(client))
#
#     try:
#         async for answer, _event in client:
#             if isinstance(answer, Error):
#                 logger.error("Received error: %s", answer)
#                 continue
#
#             if isinstance(answer.answer, Error):
#                 logger.error("Received error: %s", answer.answer)
#                 continue
#
#             match answer.answer.data:
#                 case ResolvedUser() as resolved_user:
#                     logger.info(
#                         "Resolved user: ID: %s; %s",
#                         resolved_user.message_id,
#                         resolved_user,
#                     )
#
#                 case _:
#                     logger.info("Received answer: %s", answer)
#                     continue
#
#     except ConnectionClosedError as e:
#         logger.info("Connection closed by the server. Reason: %s", e.rcvd.reason)
#
#     finally:
#         _task.cancel()
#
#     return await _task
#
#
# if __name__ == "__main__":
#     while True:
#         app = PQCowClient()
#
#         close_reason = asyncio.run(
#             app.run_async(),
#             # start_client(
#             #     "127.0.0.1",
#             #     8080,
#             #     user_ident_name="Andrew",
#             #     server_ident_name="server",
#             #     storage_path=Path("storage.enc"),
#             #     storage_key=input("Enter storage key: "),
#             # ),
#         )
#         __import__("sys").exit(0)
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
#             case CloseReason.LOCAL_ERROR:
#                 break
#
#     logger.info("Exiting client...")
