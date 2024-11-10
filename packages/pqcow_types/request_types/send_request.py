from datetime import datetime

import msgspec

from pqcow_types.request_types import SendMessage

REQUEST_TYPES = SendMessage


class SendRequest(msgspec.Struct, kw_only=True, tag=True):
    date: datetime = msgspec.field(default_factory=datetime.now)
    request: REQUEST_TYPES
