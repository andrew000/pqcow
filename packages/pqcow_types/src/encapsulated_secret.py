from msgspec import Struct


class EncapsulatedSecret(Struct, kw_only=True, tag=True):
    encapsulated_secret: bytes
