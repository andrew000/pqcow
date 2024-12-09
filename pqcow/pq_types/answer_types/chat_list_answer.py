from datetime import datetime

from msgspec import Struct


class Chat(Struct, kw_only=True, tag=True):
    id: int
    user_id: int
    chat_with_user_id: int
    created_at: datetime


class ChatListAnswer(Struct, kw_only=True, tag=True):
    chats: list[Chat]
