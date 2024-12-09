from typing import Union
from uuid import UUID

import msgspec

from pqcow.pq_types.request_types import SendMessage
from pqcow.pq_types.request_types.chat_list import ChatList
from pqcow.pq_types.request_types.poll_messages import PollMessages
from pqcow.pq_types.request_types.register_request import RegisterRequest
from pqcow.pq_types.request_types.resolve_user import ResolveUserByDilithium

REQUEST_TYPES = Union[  # noqa: UP007
    SendMessage | RegisterRequest | ResolveUserByDilithium | PollMessages | ChatList
]


class SendRequest(msgspec.Struct, kw_only=True, tag=True):
    event_id: UUID
    request: REQUEST_TYPES
