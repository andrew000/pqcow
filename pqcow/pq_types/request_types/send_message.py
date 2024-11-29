from msgspec import Struct


class SendMessage(Struct, kw_only=True, tag=True):
    user_id: int
    sign: bytes
    text: str
