from msgspec import Struct


class PollMessages(Struct, kw_only=True, tag=True):
    chat_id: int
    last_message_id: int
