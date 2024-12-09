from datetime import datetime

from msgspec import Struct


class Message(Struct, kw_only=True, tag=True):
    message_id: int
    chat_id: int
    sender_id: int
    receiver_id: int
    text: str
    sign: bytes
    created_at: datetime


class SendMessageAnswer(Struct, kw_only=True, tag=True):
    message: Message
