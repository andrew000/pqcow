from __future__ import annotations

from abc import ABCMeta, abstractmethod
from typing import TYPE_CHECKING, Literal, Self

from msgspec import Struct

if TYPE_CHECKING:
    from pathlib import Path


class Key(Struct, kw_only=True):
    identity: str
    key: bytes


class BaseKeyStorage(metaclass=ABCMeta):
    def __init__(self, path: Path, salt: str | bytes) -> None:
        self.path = path
        self._salt = salt if isinstance(salt, bytes) else salt.encode()
        self._storage: dict[str, Key] = {}

    @abstractmethod
    def create_storage(self, password: str) -> Literal[True]: ...

    @abstractmethod
    def load_storage(self, password: str) -> Self: ...

    @abstractmethod
    def save_storage(self, password: str) -> bool: ...

    @abstractmethod
    def close_storage(self) -> bool: ...

    @abstractmethod
    def get_key(self, identity: str) -> Key: ...

    @abstractmethod
    def set_key(self, identity: str, key: bytes) -> bool: ...

    @abstractmethod
    def del_key(self, identity: str) -> bool: ...
