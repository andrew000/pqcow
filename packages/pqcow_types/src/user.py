from msgspec import Struct


class User(Struct, kw_only=True, tag=True):
    id: int
    username: str | None
    first_name: str
