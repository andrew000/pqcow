from msgspec import Struct


class Error(Struct, kw_only=True, tag=True):
    code: int
    message: str
