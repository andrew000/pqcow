from __future__ import annotations

import logging
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
logger.setLevel(logging.INFO)


def create_hkdf(salt: bytes) -> HKDF:
    return HKDF(
        algorithm=SHA3_512(),
        length=32,
        salt=salt,
        info=None,
    )


async def key_exchange(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bytes:
    handshake_bytes = await reader.read(1024)
    handshake: HandShake = msgspec.msgpack.decode(handshake_bytes, type=HandShake)

    client_kem = oqs.KeyEncapsulation("Kyber512")
    encapsulated_secret, shared_secret = client_kem.encap_secret(handshake.public_key)
    encapsulated_secret = msgspec.msgpack.encode(EncapsulatedSecret(encapsulated_secret=encapsulated_secret))

    writer.write(encapsulated_secret)
    await writer.drain()

    logger.info("Shared Secret: %s", shared_secret)
    return shared_secret
