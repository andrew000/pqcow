from __future__ import annotations

import logging
import secrets
from typing import TYPE_CHECKING

import msgspec.msgpack
import oqs  # type: ignore[import-untyped]
from cryptography.hazmat.primitives.hashes import SHA3_512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pqcow_types.src.encapsulated_secret import EncapsulatedSecret
from pqcow_types.src.handshake import HandShake

if TYPE_CHECKING:
    import asyncio

logger = logging.getLogger(__name__)


def create_hkdf() -> tuple[HKDF, bytes]:
    salt = secrets.token_bytes(16)
    hkdf = HKDF(
        algorithm=SHA3_512(),
        length=32,
        salt=salt,
        info=None,
    )
    return hkdf, salt


async def key_exchange(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bytes:
    server_kem = oqs.KeyEncapsulation("Kyber512")
    public_key = server_kem.generate_keypair()

    handshake = msgspec.msgpack.encode(HandShake(public_key=public_key))

    writer.write(handshake)
    await writer.drain()

    encapsulated_secret = await reader.read(1024)  # Wait for the client to send the encrypted secret
    encapsulated_secret = msgspec.msgpack.decode(encapsulated_secret, type=EncapsulatedSecret)
    shared_secret = server_kem.decap_secret(encapsulated_secret.encapsulated_secret)

    logger.info("Shared Secret: %s", shared_secret)
    return shared_secret
