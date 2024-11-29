from typing import Union
from uuid import UUID

import msgspec

from pqcow.pq_types.request_types import SendMessage
from pqcow.pq_types.request_types.register_request import RegisterRequest
from pqcow.pq_types.request_types.resolve_user import ResolveUserByDilithium

REQUEST_TYPES = Union[SendMessage | RegisterRequest | ResolveUserByDilithium]  # noqa: UP007


class SendRequest(msgspec.Struct, kw_only=True, tag=True):
    event_id: UUID
    request: REQUEST_TYPES
