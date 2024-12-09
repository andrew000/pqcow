from msgspec import Struct

from pqcow.pq_types.answer_types.message import Message


class PollMessagesAnswer(Struct, kw_only=True, tag=True):
    chat_id: int
    messages: list[Message]
