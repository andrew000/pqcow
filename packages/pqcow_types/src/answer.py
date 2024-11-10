from datetime import datetime

import msgspec

from pqcow_types.src.encapsulated_secret import EncapsulatedSecret
from pqcow_types.src.error import Error
from pqcow_types.src.handshake import HandShake
from pqcow_types.src.message import Message


class Answer(msgspec.Struct, kw_only=True, tag=True):
    date: datetime = msgspec.field(default_factory=datetime.now)
    answer: HandShake | Message | EncapsulatedSecret | Error
