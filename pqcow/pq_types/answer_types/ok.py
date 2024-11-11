from msgspec import Struct


class OK(Struct, kw_only=True, tag=True):
    pass
