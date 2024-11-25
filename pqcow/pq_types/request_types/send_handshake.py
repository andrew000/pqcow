from msgspec import Struct


class SendHandshake(Struct, kw_only=True, tag=True):
    encapsulated_secret: bytes
    dilithium_public_key: bytes
    username: str
    sign: bytes
