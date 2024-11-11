from uuid import UUID

import msgspec

from pqcow.pq_types.request_types import SendMessage

REQUEST_TYPES = SendMessage


class SendRequest(msgspec.Struct, kw_only=True, tag=True):
    event_id: UUID
    request: REQUEST_TYPES
