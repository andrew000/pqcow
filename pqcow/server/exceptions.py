class SignatureVerificationError(Exception):
    def __init__(self, dilithium_public_key: bytes) -> None:
        super().__init__("Signature verification failed")
        self.dilithium_public_key: bytes = dilithium_public_key


class UserNotFoundError(Exception):
    def __init__(self, user_id: int) -> None:
        super().__init__(f"User with user_id {user_id} not found")
        self.user_id: int = user_id


class UserAlreadyExistsError(Exception):
    def __init__(self, username: str) -> None:
        super().__init__(f"User with username {username} already exists")
        self.username: str = username
