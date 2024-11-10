from msgspec import Struct


class Message(Struct, kw_only=True, tag=True):
    text: str
