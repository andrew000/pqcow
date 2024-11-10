from datetime import datetime

import msgspec

from pqcow_types.answer_types.error import Error
from pqcow_types.answer_types.ok import OK


class Answer(msgspec.Struct, kw_only=True, tag=True):
    date: datetime = msgspec.field(default_factory=datetime.now)
    answer: OK | Error
