from msgspec import Struct

from pqcow.pq_types.answer_types.chat_list_answer import ChatListAnswer
from pqcow.pq_types.answer_types.message import SendMessageAnswer
from pqcow.pq_types.answer_types.poll_messages_answer import PollMessagesAnswer
from pqcow.pq_types.answer_types.resolved_user import ResolvedUser


class OK(Struct, kw_only=True, tag=True):
    data: None | ResolvedUser | ChatListAnswer | PollMessagesAnswer | SendMessageAnswer
