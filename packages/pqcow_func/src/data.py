from __future__ import annotations

import secrets
import struct
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.padding import PKCS7

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from websockets.asyncio.client import ClientConnection
    from websockets.asyncio.server import ServerConnection


def encrypt_data(key: AESGCM, plaintext: bytes) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)

    padder = PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = key.encrypt(nonce, padded_data, None)

    return nonce, ciphertext


def decrypt_data(key: AESGCM, nonce: bytes, ciphertext: bytes) -> bytes:
    padded_data = key.decrypt(nonce, ciphertext, None)

    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


async def send_data(connection: ClientConnection | ServerConnection, key: AESGCM, data: bytes) -> None:
    nonce, ciphertext = encrypt_data(key, data)
    packed_data = struct.pack("!I", len(nonce)) + nonce + ciphertext

    await connection.send(packed_data)


async def receive_data(key: AESGCM, data: bytes) -> bytes:
    nonce_len, encrypted_data = struct.unpack("!I", data[:4])[0], data[4:]
    nonce, ciphertext = encrypted_data[:nonce_len], encrypted_data[nonce_len:]

    return decrypt_data(key, nonce, ciphertext)
