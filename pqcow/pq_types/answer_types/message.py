from msgspec import Struct


class Message(Struct, kw_only=True, tag=True):
    user_id: int
    text: str
    sign: bytes
