from __future__ import annotations

from abc import ABCMeta, abstractmethod
from typing import TYPE_CHECKING, Literal, Self

from msgspec import Struct

if TYPE_CHECKING:
    from pathlib import Path


class Key(Struct, kw_only=True):
    name: str
    dilithium_public_key: bytes
    dilithium_private_key: bytes


class BaseKeyStorage(metaclass=ABCMeta):
    def __init__(self, path: Path) -> None:
        self.path = path
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
    def get_key(self, name: str) -> Key: ...

    @abstractmethod
    def set_key(self, *, name: str, public_key: bytes, private_key: bytes) -> Literal[True]: ...

    @abstractmethod
    def del_key(self, name: str) -> bool: ...
