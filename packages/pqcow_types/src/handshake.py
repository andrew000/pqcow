from msgspec import Struct


class HandShake(Struct, kw_only=True, tag=True):
    public_key: bytes
