from typing import Union
from uuid import UUID

import msgspec

from pqcow.pq_types.request_types import SendMessage
from pqcow.pq_types.request_types.register_request import RegisterRequest

REQUEST_TYPES = Union[SendMessage | RegisterRequest]  # noqa: UP007


class SendRequest(msgspec.Struct, kw_only=True, tag=True):
    event_id: UUID
    request: REQUEST_TYPES
