from msgspec import Struct


class ChatList(Struct, kw_only=True, tag=True):
    pass
