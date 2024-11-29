from msgspec import Struct

from pqcow.pq_types.answer_types.resolved_user import ResolvedUser


class OK(Struct, kw_only=True, tag=True):
    data: None | ResolvedUser
