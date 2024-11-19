from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Literal, Self

import msgspec.msgpack
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from pqcow.key_storage.base import BaseKeyStorage, Key

if TYPE_CHECKING:
    from pathlib import Path


class JSONKeyStorage(BaseKeyStorage):
    def __init__(self, path: Path, salt: str | bytes) -> None:
        super().__init__(path, salt)

    def create_storage(self, password: str) -> Literal[True]:
        if self.path.exists():
            msg = "Storage already exists"
            raise ValueError(msg)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(key)
        data = fernet.encrypt(msgspec.json.encode({}))

        self.path.write_bytes(data)
        return True

    def load_storage(self, password: str) -> Self:
        if self._storage:
            msg = "Storage is already loaded"
            raise ValueError(msg)

        if not self.path.exists():
            msg = "Storage does not exist. Use create_storage() to create a new storage"
            raise FileNotFoundError(msg)

        data = self.path.read_bytes()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(key)

        self._storage.update(msgspec.json.decode(fernet.decrypt(data), type=dict[str, Key]))
        return self

    def save_storage(self, password: str, close: bool = False) -> bool:
        if not self._storage:
            msg = "Storage is empty"
            raise ValueError(msg)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        fernet = Fernet(key)
        data = fernet.encrypt(msgspec.json.encode(self._storage))

        self.path.write_bytes(data)

        if close:
            self.close_storage()

        return True

    def close_storage(self) -> bool:
        self._storage.clear()
        return True

    def get_key(self, identity: str) -> Key:
        return self._storage[identity]

    def set_key(self, identity: str, key: bytes) -> bool:
        self._storage[identity] = Key(identity=identity, key=key)
        return True

    def del_key(self, identity: str) -> bool:
        del self._storage[identity]
        return True
