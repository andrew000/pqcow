from msgspec import Struct


class ResolveUserByDilithium(Struct, kw_only=True, tag=True):
    dilithium_public_key: bytes
