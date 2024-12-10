from __future__ import annotations

import asyncio
import logging
from enum import Enum
from typing import TYPE_CHECKING

import oqs  # type: ignore[import-untyped]
from websockets import ConnectionClosed, ConnectionClosedError

from pqcow.client import AsyncClient
from pqcow.client.db.base import Base, create_sqlite_session_pool
from pqcow.client.db.db import ClientDatabase
from pqcow.pq_types.answer_types import Error
from pqcow.pq_types.answer_types.chat_list_answer import ChatListAnswer
from pqcow.pq_types.answer_types.message import SendMessageAnswer
from pqcow.pq_types.answer_types.poll_messages_answer import PollMessagesAnswer
from pqcow.pq_types.answer_types.resolved_user import ResolvedUser

if TYPE_CHECKING:
    from pqcow.client.db.models import IdentityModel


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
    return input(text).strip()


async def sender(client: AsyncClient) -> CloseReason:
    try:
        while True:
            message = await asyncio.to_thread(recv_user_input, "Enter command: ")
            try:
                match message:
                    case "/help":
                        logger.info(
                            "/help - show this help message\n"
                            "/exit - exit client\n"
                            "/me - show user info\n"
                            "/resolve - resolve user by dilithium public key\n"
                            "/send - send message to user\n"
                            "/list - list all chats\n"
                            "/poll - poll messages from chat\n",
                        )

                    case "/exit":
                        await client.close()
                        return CloseReason.CLIENT_CLOSED

                    case "/me":
                        logger.info(
                            "ID: %s, User: %s, identity: %s",
                            client.user_id,
                            client.username,
                            client.public_key.hex(),
                        )

                    case "/resolve":
                        dilithium_public_key_hex: str = await asyncio.to_thread(
                            recv_user_input,
                            "Enter dilithium public key: ",
                        )
                        try:
                            await client.resolve_user(
                                bytes.fromhex(dilithium_public_key_hex.removeprefix("0x")),
                            )
                        except ValueError:
                            logger.exception("Invalid dilithium public key")
                            continue

                    case "/send":
                        user_id = int(await asyncio.to_thread(recv_user_input, "Enter user id: "))
                        message = await asyncio.to_thread(recv_user_input, "Enter message: ")
                        await client.send_message(user_id, message)

                    case "/list":
                        await client.chat_list()

                    case "/poll":
                        chat_id = int(await asyncio.to_thread(recv_user_input, "Enter chat id: "))
                        await client.poll_messages(chat_id)

                    case _:
                        logger.info("Unknown command: %s", message)
                        continue

            except ConnectionClosed as e:
                logger.info("Connection closed by the server. Reason: %s", e.rcvd.reason)
                return CloseReason.SERVER_CLOSED

            except ValueError:
                logger.exception("Invalid input")
                continue

            except Exception as e:
                logger.exception("An error occurred while processing command: %s", e.args)
                return CloseReason.LOCAL_ERROR

            await asyncio.sleep(0.1)

    except asyncio.CancelledError:
        logger.info("Sender task was cancelled")
        return CloseReason.TASK_CANCELLED

    except Exception as e:
        logger.exception("An error occurred while sending message: %s", e.args)
        return CloseReason.ERROR


async def chat_polling(client: AsyncClient) -> None:
    while True:
        try:
            async with client.db.sessionmaker() as session:
                chat_ids = await client.db.get_chat_ids(session=session)

                for chat_id in chat_ids:
                    try:
                        await client.poll_messages(chat_id)
                    except Exception as e:
                        logger.exception("An error occurred while polling messages: %s", e.args)
                    finally:
                        await asyncio.sleep(1)

        except asyncio.CancelledError:
            logger.info("Polling task was cancelled")
            break

        except Exception as e:
            logger.exception("An error occurred while polling messages: %s", e.args)
            break


async def start_client(
    host: str,
    port: int,
    user_identity_name: str,
    server_identity_name: str,
) -> tuple[CloseReason, None]:
    db = ClientDatabase(*(await create_sqlite_session_pool()))
    await db.init_db(base_model=Base)

    user_ident: IdentityModel = await db.get_identity(user_identity_name, type_="client")

    if not user_ident:
        logger.info(
            "Identity key for user `%s` not found. Would you like to create one?",
            user_identity_name,
        )
        create = input("[Y/n]: ")

        if create.casefold() != "y":
            return CloseReason.ERROR, None

        logger.info("Creating Identity key for user `%s`...", user_identity_name)

        public_key, private_key = create_dilithium_keypair()
        user_ident = await db.new_identity(
            user_identity_name,
            type_="client",
            public_key=public_key,
            private_key=private_key,
        )

        logger.info("Identity key for user `%s` created and saved", user_identity_name)

    server_ident = await db.get_identity(server_identity_name, type_="server")

    if not server_ident:
        logger.info(
            "Identity key for server `%s` not found. Would you like to add one?",
            server_identity_name,
        )
        create = input("[Y/n]: ")

        if create.casefold() != "y":
            return CloseReason.ERROR, None

        server_ident_input = input("Enter server dilithium public key in hex: ")

        try:
            server_ident_bytes = bytes.fromhex(server_ident_input)
        except ValueError:
            logger.exception("Invalid dilithium public key")
            return CloseReason.ERROR, None

        server_ident = await db.new_identity(
            server_identity_name,
            type_="server",
            public_key=server_ident_bytes,
        )

        logger.info("Identity key for server `%s` added and saved", server_identity_name)

    logger.info(
        "Loaded Identity key for user `%s`; %s",
        user_ident.username,
        user_ident.dilithium_public_key.hex()[:32],
    )
    logger.info(
        "Loaded Identity key for server `%s`; %s",
        server_identity_name,
        server_ident.dilithium_public_key.hex()[:32],
    )

    client = AsyncClient(
        host=host,
        port=port,
        signature=oqs.Signature("Dilithium3", user_ident.dilithium_private_key),
        public_key=user_ident.dilithium_public_key,
        username=user_identity_name,
        db=db,
        server_dilithium_public_key=server_ident.dilithium_public_key,
    )

    try:
        await client.connect()
    except ConnectionRefusedError:
        logger.info("Could not connect to server at %s:%s", host, port)
        return CloseReason.ERROR, None

    try:
        await client.register()
    except Exception as e:
        logger.exception("An error occurred while registering: %s", type(e).mro())
        return CloseReason.ERROR, None

    _sender_task = asyncio.create_task(sender(client))
    _polling_task = asyncio.create_task(chat_polling(client))

    await client.resolve_user(client.public_key)

    try:
        async for answer, _event in client:
            if isinstance(answer, Error):
                logger.error("Received error: %s", answer)
                continue

            if isinstance(answer.answer, Error):
                logger.error("Received error: %s", answer.answer)
                continue

            match answer.answer.data:
                case ResolvedUser() as resolved_user:
                    if resolved_user.dilithium_public_key == client.public_key:
                        client.user_id = resolved_user.id
                        logger.info(
                            "Resolved user: ID: %s; %s",
                            resolved_user.id,
                            resolved_user.username,
                        )
                        continue

                    async with client.db.sessionmaker() as session:
                        await client.db.new_user(
                            session=session,
                            user_id=resolved_user.id,
                            username=resolved_user.username,
                            dilithium_public_key=resolved_user.dilithium_public_key,
                        )

                    logger.info(
                        "Resolved user: ID: %s; %s",
                        resolved_user.id,
                        resolved_user.username,
                    )

                case ChatListAnswer() as chat_list:
                    logger.info(
                        "Chat list: %s",
                        [f"{chat.id=}: {chat.chat_with_user_id=}" for chat in chat_list.chats],
                    )

                    async with client.db.sessionmaker() as session:
                        await client.db.batch_insert_chats(
                            session=session,
                            chat_list=chat_list,
                        )

                case PollMessagesAnswer() as poll_messages:
                    if not poll_messages.messages:
                        continue

                    async with client.db.sessionmaker() as session:
                        await client.db.batch_insert_messages(
                            session=session,
                            messages=poll_messages.messages,
                        )

                    logger.info(
                        "Poll messages: %s",
                        [
                            f"{message.sender_id} -> {message.receiver_id}: {message.text}"
                            for message in poll_messages.messages
                        ],
                    )

                case SendMessageAnswer() as message_sent:
                    async with client.db.sessionmaker() as session:
                        await client.db.new_message_in_chat(
                            session=session,
                            message_id=message_sent.message.message_id,
                            chat_id=message_sent.message.chat_id,
                            sender_id=message_sent.message.sender_id,
                            receiver_id=message_sent.message.receiver_id,
                            message=message_sent.message.text,
                            signature=message_sent.message.sign,
                            created_at=message_sent.message.created_at,
                        )

                    logger.info(
                        "Message sent: [%s -> %s]: %s",
                        message_sent.message.sender_id,
                        message_sent.message.receiver_id,
                        message_sent.message.text,
                    )

                case _:
                    logger.info("Received answer: %s", answer)
                    continue

    except ConnectionClosedError as e:
        logger.info("Connection closed by the server. Reason: %s", e.rcvd.reason)

    finally:
        _sender_task.cancel()
        _polling_task.cancel()

    return await _sender_task, await _polling_task


if __name__ == "__main__":
    while True:
        close_reason, _ = asyncio.run(
            start_client(
                "127.0.0.1",
                8080,
                user_identity_name=input("Enter your identity name: ").strip(),
                server_identity_name="master",
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
