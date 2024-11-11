from msgspec import Struct


class Handshake(Struct, kw_only=True, tag=True):
    public_key: bytes
