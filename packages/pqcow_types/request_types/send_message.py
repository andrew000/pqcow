from msgspec import Struct


class SendMessage(Struct, kw_only=True, tag=True):
    chat_id: int | str
    text: str
