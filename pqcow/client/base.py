from __future__ import annotations

from abc import ABCMeta, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from oqs import Signature  # type: ignore[import-untyped]

    from pqcow.pq_types.request_types import REQUEST_TYPES


class BaseSyncClient(metaclass=ABCMeta):
    @abstractmethod
    def __init__(self, host: str, port: int, signature: Signature | None = None) -> None: ...

    @abstractmethod
    def connect(self) -> None: ...

    @abstractmethod
    def close(self) -> None: ...

    @abstractmethod
    def do_handshake(self) -> None: ...

    @abstractmethod
    def send_request(self, request: REQUEST_TYPES) -> None: ...

    @abstractmethod
    def send_message(self, chat_id: int | str, text: str) -> None: ...


class BaseAsyncClient(metaclass=ABCMeta):
    @abstractmethod
    def __init__(self, host: str, port: int, signature: Signature, username: str) -> None: ...

    @abstractmethod
    async def connect(self) -> None: ...

    @abstractmethod
    async def close(self) -> None: ...

    @abstractmethod
    async def do_handshake(self, signature: Signature) -> None: ...

    @abstractmethod
    async def send_request(self, request: REQUEST_TYPES) -> None: ...

    @abstractmethod
    async def send_message(self, user_id: int | str, text: str) -> None: ...
