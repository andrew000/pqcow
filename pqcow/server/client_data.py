from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class UnregisteredClientData:
    dilithium_public_key: bytes
    shared_secret: AESGCM


@dataclass
class ClientData:
    user_id: int
    username: str
    dilithium_public_key: bytes
    shared_secret: AESGCM
