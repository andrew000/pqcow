from msgspec import Struct


class ResolvedUser(Struct, kw_only=True, tag=True):
    id: int
    username: str
    dilithium_public_key: bytes
