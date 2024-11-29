from __future__ import annotations

import secrets
import struct
from typing import TYPE_CHECKING

import msgspec.msgpack
from cryptography.hazmat.primitives.padding import PKCS7
from msgspec import Struct

from pqcow.pq_types.signed_data import SignedData

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from oqs import Signature  # type: ignore[import-untyped]


def encrypt_data(shared_secret: AESGCM, plaintext: bytes) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(nbytes=12)

    padder = PKCS7(block_size=128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = shared_secret.encrypt(nonce, padded_data, None)

    return nonce, ciphertext


def decrypt_data(shared_secret: AESGCM, nonce: bytes, ciphertext: bytes) -> bytes:
    padded_data = shared_secret.decrypt(nonce, ciphertext, None)

    unpadder = PKCS7(block_size=128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def prepare_data_to_send(shared_secret: AESGCM, sign: Signature, data: bytes | Struct) -> bytes:
    if isinstance(data, Struct):
        data = msgspec.msgpack.encode(data)

    data = sign_data(sign, data)
    nonce, ciphertext = encrypt_data(shared_secret, data)

    return struct.pack("!I", len(nonce)) + nonce + ciphertext


def sign_data(signature: Signature, data: bytes) -> bytes:
    return msgspec.msgpack.encode(SignedData(data=data, sign=signature.sign(data)))


def pre_process_incom_data(*, shared_secret: AESGCM, data: bytes) -> SignedData:
    nonce_len, encrypted_data = struct.unpack("!I", data[:4])[0], data[4:]
    nonce, ciphertext = encrypted_data[:nonce_len], encrypted_data[nonce_len:]

    return msgspec.msgpack.decode(decrypt_data(shared_secret, nonce, ciphertext), type=SignedData)
