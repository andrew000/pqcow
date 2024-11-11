from uuid import UUID, uuid4

import msgspec

from pqcow.pq_types.answer_types.error import Error
from pqcow.pq_types.answer_types.ok import OK


class Answer(msgspec.Struct, kw_only=True, tag=True):
    event_id: UUID = msgspec.field(default_factory=uuid4)
    answer: OK | Error
