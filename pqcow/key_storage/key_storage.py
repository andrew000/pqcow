from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Literal, Self

import msgspec.msgpack
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pqcow.key_storage.base import BaseKeyStorage, Key

if TYPE_CHECKING:
    from pathlib import Path


class JSONKeyStorage(BaseKeyStorage):
    def __init__(self, path: Path) -> None:
        super().__init__(path)

    def create_storage(self, storage_key: str | bytes) -> Literal[True]:
        if self.path.exists():
            msg = "Storage already exists"
            raise ValueError(msg)

        if isinstance(storage_key, str):
            storage_key = storage_key.encode()

        kdf = HKDF(algorithm=hashes.SHA3_512(), length=32, salt=None, info=b"pqcow")
        fernet = Fernet(base64.urlsafe_b64encode(kdf.derive(storage_key)))

        data = fernet.encrypt(msgspec.json.encode({}))
        self.path.write_bytes(data)
        return True

    def load_storage(self, storage_key: str | bytes) -> Self:
        if self._storage:
            msg = "Storage is already loaded"
            raise ValueError(msg)

        if not self.path.exists():
            msg = "Storage does not exist. Use create_storage() to create a new storage"
            raise FileNotFoundError(msg)

        if isinstance(storage_key, str):
            storage_key = storage_key.encode()

        kdf = HKDF(algorithm=hashes.SHA3_512(), length=32, salt=None, info=b"pqcow")
        fernet = Fernet(base64.urlsafe_b64encode(kdf.derive(storage_key)))

        data = self.path.read_bytes()
        self._storage.update(msgspec.json.decode(fernet.decrypt(data), type=dict[str, Key]))

        return self

    def save_storage(self, password: str | bytes, close: bool = False) -> bool:
        if not self._storage:
            msg = "Storage is empty"
            raise ValueError(msg)

        if isinstance(password, str):
            password = password.encode()

        kdf = HKDF(algorithm=hashes.SHA3_512(), length=32, salt=None, info=b"pqcow")
        fernet = Fernet(base64.urlsafe_b64encode(kdf.derive(password)))

        data = fernet.encrypt(msgspec.json.encode(self._storage))
        self.path.write_bytes(data)

        if close:
            self.close_storage()

        return True

    def close_storage(self) -> bool:
        self._storage.clear()
        return True

    def get_key(self, name: str) -> Key:
        return self._storage[name]

    def set_key(self, *, name: str, public_key: bytes, private_key: bytes) -> Literal[True]:
        self._storage[name] = Key(
            name=name,
            dilithium_public_key=public_key,
            dilithium_private_key=private_key,
        )
        return True

    def del_key(self, name: str) -> bool:
        del self._storage[name]
        return True
