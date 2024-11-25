from msgspec import Struct


class SignedData(Struct, kw_only=True, tag=True):
    data: bytes
    sign: bytes
