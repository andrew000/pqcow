from msgspec import Struct


class RegisterRequest(Struct, kw_only=True, tag=True):
    username: str
