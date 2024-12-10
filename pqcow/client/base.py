from __future__ import annotations

from abc import ABCMeta, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from oqs import Signature  # type: ignore[import-untyped]

    from pqcow.pq_types.request_types import REQUEST_TYPES


class BaseAsyncClient(metaclass=ABCMeta):
    @abstractmethod
    def __init__(
        self,
        host: str,
        port: int,
        signature: Signature,
        public_key: bytes,
        username: str,
        server_dilithium_public_key: bytes | None = None,
        force_retrieve_server_public_key: bool = False,
    ) -> None: ...

    @abstractmethod
    async def connect(self) -> None: ...

    @abstractmethod
    async def close(self) -> None: ...

    @abstractmethod
    async def do_handshake(self, signature: Signature) -> None: ...

    @abstractmethod
    async def __call__(self, request: REQUEST_TYPES) -> None: ...

    @abstractmethod
    async def register(self) -> None: ...

    @abstractmethod
    async def resolve_user(self, dilithium_public_key: bytes) -> None: ...

    @abstractmethod
    async def send_message(self, user_id: int, text: str) -> None: ...

    @abstractmethod
    async def chat_list(self) -> None: ...

    @abstractmethod
    async def poll_messages(self, chat_id: int) -> None: ...
