from msgspec import Struct


class Handshake(Struct, kw_only=True, tag=True):
    kyber_public_key: bytes
    dilithium_public_key: bytes
