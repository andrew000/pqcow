from __future__ import annotations

import secrets
import struct
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.padding import PKCS7

if TYPE_CHECKING:
    from asyncio import StreamReader, StreamWriter


def encrypt_data(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)

    padder = PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = aesgcm.encrypt(nonce, padded_data, None)

    return nonce, ciphertext


def decrypt_data(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    padded_data = aesgcm.decrypt(nonce, ciphertext, None)

    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


async def send_data(writer: StreamWriter, ciphertext: bytes, nonce: bytes) -> None:
    # Send length of data
    writer.write(struct.pack("!I", len(nonce)))
    writer.write(struct.pack("!I", len(ciphertext)))

    writer.write(nonce + ciphertext)

    await writer.drain()


async def receive_data(reader: StreamReader) -> tuple[bytes, bytes]:
    # Read length of data
    nonce = struct.unpack("!I", await reader.readexactly(4))[0]
    ciphertext_len = struct.unpack("!I", await reader.readexactly(4))[0]
    # tag_len = struct.unpack("!I", await reader.readexactly(4))[0]

    nonce = await reader.readexactly(nonce)
    ciphertext = await reader.readexactly(ciphertext_len)
    # tag = await reader.readexactly(tag_len)

    return nonce, ciphertext
