from __future__ import annotations

from typing import TYPE_CHECKING

import msgspec

from pqcow_func.src.data import decrypt_data, encrypt_data, receive_data, send_data
from pqcow_types.src.answer import Answer
from pqcow_types.src.request import Request

if TYPE_CHECKING:
    from asyncio.streams import StreamReader, StreamWriter


async def send_request(writer: StreamWriter, key: bytes, request: Request) -> None:
    nonce, ciphertext = encrypt_data(key, msgspec.msgpack.encode(request))
    await send_data(writer, ciphertext, nonce)


async def send_answer(writer: StreamWriter, key: bytes, answer: Answer) -> None:
    nonce, ciphertext = encrypt_data(key, msgspec.msgpack.encode(answer))
    await send_data(writer, ciphertext, nonce)


async def receive_request(reader: StreamReader, key: bytes) -> Request:
    nonce, ciphertext = await receive_data(reader)
    decrypted_data = decrypt_data(key, nonce, ciphertext)
    return msgspec.msgpack.decode(decrypted_data, type=Request)


async def receive_answer(reader: StreamReader, key: bytes) -> Answer:
    nonce, ciphertext = await receive_data(reader)
    decrypted_data = decrypt_data(key, nonce, ciphertext)
    return msgspec.msgpack.decode(decrypted_data, type=Answer)
